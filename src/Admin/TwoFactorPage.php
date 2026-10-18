<?php
/**
 * Each user's two-factor setup page, profile section and reminder.
 *
 * phpcs:disable WordPress.Security.NonceVerification -- handle() calls check_admin_referer()
 * first; the profile hook runs inside WordPress's own nonce-checked profile update.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Admin;

use SentinelShield\Container;
use SentinelShield\Repository\EventRepository;
use SentinelShield\Settings;
use SentinelShield\TwoFactor\QrCode;
use SentinelShield\TwoFactor\Totp;
use SentinelShield\TwoFactor\TwoFactorLogin;
use SentinelShield\TwoFactor\UserTwoFactor;

defined( 'ABSPATH' ) || exit;

/**
 * Users → Two-Factor Authentication (Profile → ... for users who cannot list
 * users). Every change applies to the logged-in user's own account; removing a
 * method or replacing backup codes needs the current password. Administrators
 * can reset another user's two-factor from that user's profile.
 */
final class TwoFactorPage {

	public const SLUG   = 'sentinel-shield-2fa';
	public const ACTION = 'sentinel_shield_2fa_user';

	/**
	 * Constructor.
	 *
	 * @param Container $c Services.
	 */
	public function __construct( private Container $c ) {}

	/**
	 * Hooks the page, handlers, profile section and reminder.
	 */
	public function register(): void {
		add_action( 'admin_menu', array( $this, 'menu' ) );
		add_action( 'user_admin_menu', array( $this, 'menu' ) );
		add_action( 'admin_post_' . self::ACTION, array( $this, 'handle' ) );
		add_action( 'show_user_profile', array( $this, 'profile_section' ) );
		add_action( 'edit_user_profile', array( $this, 'profile_section' ) );
		add_action( 'edit_user_profile_update', array( $this, 'profile_reset' ) );
		foreach ( array( 'admin_notices', 'network_admin_notices', 'user_admin_notices' ) as $hook ) {
			add_action( $hook, array( $this, 'reminder' ) );
		}
	}

	/**
	 * URL of the page.
	 */
	public static function url(): string {
		$base = is_network_admin() ? network_admin_url( 'users.php' ) : ( is_user_admin() ? user_admin_url( 'profile.php' ) : admin_url( current_user_can( 'list_users' ) ? 'users.php' : 'profile.php' ) );
		return add_query_arg( 'page', self::SLUG, $base );
	}

	/**
	 * Adds the page under Users (or Profile).
	 */
	public function menu(): void {
		add_users_page( __( 'Two-Factor Authentication', 'sentinel-shield' ), __( 'Two-Factor Authentication', 'sentinel-shield' ), 'read', self::SLUG, array( $this, 'render' ) );
	}

	/**
	 * Dashboard reminder for accounts that must set up two-factor authentication.
	 */
	public function reminder(): void {
		$user   = wp_get_current_user();
		$screen = get_current_screen();
		if ( ! $user->exists() || ( $screen && str_contains( (string) $screen->id, self::SLUG ) ) || ! $this->login()->setup_missing( $user ) ) {
			return;
		}
		$text = $this->login()->email_allowed()
			? __( 'Your account must use two-factor authentication. Until you set up an authenticator app, a code is emailed to you at every login.', 'sentinel-shield' )
			: __( 'Your account must use two-factor authentication. Please set it up now.', 'sentinel-shield' );
		echo '<div class="notice notice-warning"><p><strong>' . esc_html__( 'Two-factor authentication:', 'sentinel-shield' ) . '</strong> ' . esc_html( $text ) . ' <a class="button button-primary" href="' . esc_url( self::url() ) . '">' . esc_html__( 'Set up two-factor authentication', 'sentinel-shield' ) . '</a></p></div>';
	}

	/**
	 * Renders the setup page.
	 */
	public function render(): void {
		$user    = wp_get_current_user();
		$id      = (int) $user->ID;
		$users   = $this->users();
		$login   = $this->login();
		$summary = $users->summary( $id );
		$methods = $login->methods( $user );
		$codes   = View::take_result( '2fa_backup_codes' );

		echo '<div class="wrap ss-wrap"><h1>' . esc_html__( 'Two-Factor Authentication', 'sentinel-shield' ) . '</h1>';
		View::render_flash();
		echo '<p>' . esc_html__( 'Two-factor authentication asks for a code after your password, so a stolen or guessed password alone is not enough to log in to your account.', 'sentinel-shield' ) . '</p>';
		if ( ! $this->settings()->is_enabled() || ! $this->settings()->is_module_enabled( 'two_factor' ) ) {
			echo '<div class="notice notice-warning inline"><p>' . esc_html__( 'Two-factor authentication is switched off on this site at the moment, so no code is asked for.', 'sentinel-shield' ) . '</p></div>';
		}
		if ( $login->required( $user ) ) {
			echo '<div class="notice notice-info inline"><p>' . esc_html__( 'Two-factor authentication is required for your account.', 'sentinel-shield' ) . '</p></div>';
		}
		echo '<p class="ss-big">' . esc_html__( 'Status:', 'sentinel-shield' ) . ' ';
		echo $login->needs_second_step( $user ) ? View::pill( __( 'On', 'sentinel-shield' ), 'ok' ) : View::pill( __( 'Off', 'sentinel-shield' ), 'warn' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- pill() escapes.
		echo '</p>';

		if ( is_array( $codes ) && $codes ) {
			echo '<div class="ss-card"><h2>' . esc_html__( 'Your new backup codes', 'sentinel-shield' ) . '</h2>';
			echo '<p><strong>' . esc_html__( 'Save these now: they are shown only once.', 'sentinel-shield' ) . '</strong> ' . esc_html__( 'Each code works once, in place of a code from your app or email. Keep them somewhere safe away from your phone, such as a password manager or a printed copy.', 'sentinel-shield' ) . '</p>';
			echo '<ul class="ss-codes ss-backup-codes">';
			foreach ( $codes as $code ) {
				echo '<li><code>' . esc_html( (string) $code ) . '</code></li>';
			}
			echo '</ul></div>';
		}

		// Authenticator app.
		echo '<div class="ss-card"><h2>' . esc_html__( 'Authenticator app', 'sentinel-shield' ) . '</h2>';
		if ( $summary['totp'] ) {
			$added = (int) get_user_meta( $id, UserTwoFactor::META . 'totp_added', true );
			echo '<p>' . View::pill( __( 'Set up', 'sentinel-shield' ), 'ok' ) . ' '; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- pill() escapes.
			/* translators: %s: date. */
			echo esc_html( $added ? sprintf( __( 'Added on %s.', 'sentinel-shield' ), wp_date( (string) get_option( 'date_format' ), $added ) ) : '' ) . '</p>';
			if ( ! $summary['totp_readable'] ) {
				echo '<div class="notice notice-error inline"><p>' . esc_html__( 'Your app\'s secret can no longer be read, because this site\'s security keys (in wp-config.php) changed. Remove the app and set it up again.', 'sentinel-shield' ) . '</p></div>';
			}
			$this->form_open( 'totp_remove' );
			$this->password_field();
			submit_button( __( 'Remove authenticator app', 'sentinel-shield' ), 'delete', 'submit', false );
			echo '</form>';
		} else {
			$secret = $users->pending_secret( $id );
			$issuer = wp_specialchars_decode( (string) get_bloginfo( 'name' ), ENT_QUOTES );
			$issuer = '' === trim( $issuer ) ? (string) wp_parse_url( home_url(), PHP_URL_HOST ) : $issuer;
			$uri    = Totp::uri( $secret, $user->user_login, $issuer );
			echo '<ol class="ss-steps">';
			echo '<li>' . esc_html__( 'Install an authenticator app on your phone, e.g. Google Authenticator, Microsoft Authenticator, 2FAS, Aegis, FreeOTP, or the one built into 1Password or Bitwarden.', 'sentinel-shield' ) . '</li>';
			echo '<li>' . esc_html__( 'In the app, add an account and scan this QR code:', 'sentinel-shield' ) . '<div class="ss-qr">';
			echo QrCode::svg( $uri, 4, __( 'QR code for your authenticator app', 'sentinel-shield' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Generated SVG; the only text, the label, is escaped by QrCode::svg().
			echo '</div>' . esc_html__( 'Cannot scan it? Choose "enter a setup key" in the app and type:', 'sentinel-shield' ) . ' <code class="ss-secret">' . esc_html( Totp::format_secret( $secret ) ) . '</code> ' . esc_html__( '(time-based)', 'sentinel-shield' ) . '</li>';
			echo '<li>' . esc_html__( 'Enter the 6-digit code the app shows:', 'sentinel-shield' );
			$this->form_open( 'totp_enable' );
			echo ' <input type="text" name="code" class="regular-text ss-code-input" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9 ]{6,7}" maxlength="7" required> ';
			submit_button( __( 'Turn on', 'sentinel-shield' ), 'primary', 'submit', false );
			echo '</form></li></ol>';
			$this->form_open( 'totp_renew' );
			submit_button( __( 'Show a different QR code', 'sentinel-shield' ), 'link', 'submit', false );
			echo '</form>';
		}
		echo '</div>';

		// Email codes.
		if ( $login->email_allowed() ) {
			echo '<div class="ss-card"><h2>' . esc_html__( 'Codes by email', 'sentinel-shield' ) . '</h2>';
			/* translators: %s: email address. */
			echo '<p>' . esc_html( sprintf( __( 'Get an 8-digit code at %s each time you log in. Easier than an app, but anyone who can read your email can then log in with your password.', 'sentinel-shield' ), $user->user_email ) ) . '</p>';
			if ( $summary['email'] ) {
				echo '<p>' . View::pill( __( 'On', 'sentinel-shield' ), 'ok' ) . '</p>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- pill() escapes.
				$this->form_open( 'email_off' );
				$this->password_field();
				submit_button( __( 'Turn off codes by email', 'sentinel-shield' ), 'delete', 'submit', false );
				echo '</form>';
			} else {
				if ( in_array( 'email', $methods, true ) ) {
					echo '<p class="description">' . esc_html__( 'Because two-factor authentication is required for your account and you have no app set up, codes are already emailed to you.', 'sentinel-shield' ) . '</p>';
				}
				$this->form_open( 'email_on' );
				submit_button( __( 'Turn on codes by email', 'sentinel-shield' ), 'secondary', 'submit', false );
				echo '</form>';
			}
			echo '</div>';
		}

		// Backup codes.
		echo '<div class="ss-card"><h2>' . esc_html__( 'Backup codes', 'sentinel-shield' ) . '</h2>';
		echo '<p>' . esc_html__( 'One-time codes for when you do not have your phone. They work only together with an app or email codes.', 'sentinel-shield' ) . '</p>';
		/* translators: %d: number of codes. */
		echo '<p>' . esc_html( sprintf( _n( '%d unused code left.', '%d unused codes left.', $summary['backup'], 'sentinel-shield' ), $summary['backup'] ) ) . '</p>';
		$this->form_open( 'backup_new' );
		if ( $summary['backup'] > 0 ) {
			$this->password_field();
		}
		submit_button( $summary['backup'] > 0 ? __( 'Replace with new codes', 'sentinel-shield' ) : __( 'Create backup codes', 'sentinel-shield' ), 'secondary', 'submit', false );
		echo '</form></div>';

		// Trusted browsers.
		if ( (int) $this->settings()->get( 'twofa.remember_days', 0 ) > 0 ) {
			echo '<div class="ss-card"><h2>' . esc_html__( 'Trusted browsers', 'sentinel-shield' ) . '</h2><p>' . esc_html__( 'Browsers where you ticked "Trust this browser" are not asked for a code for a while. Forget them all if you lost a device or used a shared computer.', 'sentinel-shield' ) . '</p>';
			$this->form_open( 'forget_devices' );
			submit_button( __( 'Forget all trusted browsers', 'sentinel-shield' ), 'secondary', 'submit', false );
			echo '</form></div>';
		}
		echo '</div>';
	}

	/**
	 * Form handler; every operation is on the current user's own account.
	 */
	public function handle(): void {
		if ( ! is_user_logged_in() ) {
			wp_die( esc_html__( 'You must be logged in.', 'sentinel-shield' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( self::ACTION );
		$user  = wp_get_current_user();
		$id    = (int) $user->ID;
		$users = $this->users();
		$op    = isset( $_POST['op'] ) ? sanitize_key( wp_unslash( $_POST['op'] ) ) : '';
		$back  = isset( $_POST['back'] ) ? esc_url_raw( wp_unslash( $_POST['back'] ) ) : admin_url( 'profile.php' );

		if ( in_array( $op, array( 'totp_remove', 'email_off' ), true ) || ( 'backup_new' === $op && $users->backup_remaining( $id ) > 0 ) ) {
			$password = isset( $_POST['password'] ) ? (string) wp_unslash( $_POST['password'] ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Passwords are compared, not stored or shown.
			if ( ! wp_check_password( $password, $user->user_pass, $id ) ) {
				View::flash( 'error', __( 'Your current password was not correct. Nothing was changed.', 'sentinel-shield' ) );
				View::redirect( $back );
			}
		}

		switch ( $op ) {
			case 'totp_enable':
				$code = isset( $_POST['code'] ) ? sanitize_text_field( wp_unslash( $_POST['code'] ) ) : '';
				if ( ! $users->enable_totp( $id, $code, time() ) ) {
					View::flash( 'error', __( 'That code is not correct. Check that the time on your phone is set automatically, then try the current code.', 'sentinel-shield' ) );
					break;
				}
				View::flash( 'success', __( 'Your authenticator app is set up. From now on you will be asked for a code from it when you log in.', 'sentinel-shield' ) );
				$this->log( 'twofa_enabled', $user, __( 'Authenticator app set up', 'sentinel-shield' ) );
				$this->first_backup_codes( $id );
				break;
			case 'totp_renew':
				$users->pending_secret( $id, true );
				break;
			case 'totp_remove':
				$users->disable_totp( $id );
				View::flash( 'success', __( 'The authenticator app was removed from your account.', 'sentinel-shield' ) );
				$this->log( 'twofa_disabled', $user, __( 'Authenticator app removed', 'sentinel-shield' ) );
				break;
			case 'email_on':
				if ( ! $this->login()->email_allowed() ) {
					break;
				}
				$users->set_email( $id, true );
				View::flash( 'success', __( 'Codes by email are on. From now on a code is emailed to you when you log in (unless you use your app).', 'sentinel-shield' ) );
				$this->log( 'twofa_enabled', $user, __( 'Codes by email turned on', 'sentinel-shield' ) );
				$this->first_backup_codes( $id );
				break;
			case 'email_off':
				$users->set_email( $id, false );
				View::flash( 'success', __( 'Codes by email are off.', 'sentinel-shield' ) );
				$this->log( 'twofa_disabled', $user, __( 'Codes by email turned off', 'sentinel-shield' ) );
				break;
			case 'backup_new':
				View::put_result( '2fa_backup_codes', $users->new_backup_codes( $id ) );
				$this->log( 'twofa_enabled', $user, __( 'New backup codes created', 'sentinel-shield' ) );
				break;
			case 'forget_devices':
				$users->forget_devices( $id );
				View::flash( 'success', __( 'All trusted browsers were forgotten. Each will be asked for a code at the next login.', 'sentinel-shield' ) );
				break;
			default:
				View::flash( 'error', __( 'Unknown action.', 'sentinel-shield' ) );
		}
		View::redirect( $back );
	}

	/**
	 * Two-factor status on profile screens; on another user's profile, a reset box.
	 *
	 * @param \WP_User $user Profile owner.
	 */
	public function profile_section( $user ): void {
		if ( ! $user instanceof \WP_User ) {
			return;
		}
		$own     = get_current_user_id() === (int) $user->ID;
		$summary = $this->users()->summary( (int) $user->ID );
		$parts   = array();
		if ( $summary['totp'] ) {
			$parts[] = $summary['totp_readable'] ? __( 'authenticator app', 'sentinel-shield' ) : __( 'authenticator app (unreadable, needs setting up again)', 'sentinel-shield' );
		}
		if ( $summary['email'] ) {
			$parts[] = __( 'codes by email', 'sentinel-shield' );
		}
		if ( $summary['backup'] ) {
			/* translators: %d: number of codes. */
			$parts[] = sprintf( _n( '%d backup code', '%d backup codes', $summary['backup'], 'sentinel-shield' ), $summary['backup'] );
		}
		echo '<h2>' . esc_html__( 'Two-Factor Authentication', 'sentinel-shield' ) . '</h2><table class="form-table" role="presentation"><tr><th>' . esc_html__( 'Status', 'sentinel-shield' ) . '</th><td>';
		echo esc_html( $parts ? implode( ', ', $parts ) : __( 'Not set up', 'sentinel-shield' ) );
		if ( $this->login()->required( $user ) ) {
			echo ' <span class="description">' . esc_html__( '(required for this account)', 'sentinel-shield' ) . '</span>';
		}
		if ( $own ) {
			echo '<p><a class="button" href="' . esc_url( self::url() ) . '">' . esc_html__( 'Manage two-factor authentication', 'sentinel-shield' ) . '</a></p>';
		} elseif ( current_user_can( 'edit_user', $user->ID ) && ( $parts || $summary['totp'] ) ) {
			echo '<p><label><input type="checkbox" name="sentinel_shield_2fa_reset" value="1"> ' . esc_html__( 'Reset two-factor authentication for this user', 'sentinel-shield' ) . '</label></p>';
			echo '<p class="description">' . esc_html__( 'Removes the authenticator app, email codes, backup codes and trusted browsers, e.g. after a lost phone. If two-factor is required for the account, the user then gets codes by email until they set up a new app.', 'sentinel-shield' ) . '</p>';
		}
		echo '</td></tr></table>';
	}

	/**
	 * Applies the reset box from another user's profile.
	 *
	 * @param int $user_id Profile owner.
	 */
	public function profile_reset( $user_id ): void {
		$user_id = (int) $user_id;
		if ( empty( $_POST['sentinel_shield_2fa_reset'] ) || ! current_user_can( 'edit_user', $user_id ) || get_current_user_id() === $user_id ) {
			return;
		}
		$user = get_userdata( $user_id );
		if ( ! $user instanceof \WP_User ) {
			return;
		}
		$this->users()->reset( $user_id );
		$this->log(
			'twofa_reset',
			$user,
			/* translators: %s: administrator login. */
			sprintf( __( 'Two-factor authentication reset by %s', 'sentinel-shield' ), wp_get_current_user()->user_login )
		);
	}

	/**
	 * Creates backup codes when the first method is added and none exist.
	 *
	 * @param int $user_id User.
	 */
	private function first_backup_codes( int $user_id ): void {
		if ( 0 === $this->users()->backup_remaining( $user_id ) ) {
			View::put_result( '2fa_backup_codes', $this->users()->new_backup_codes( $user_id ) );
		}
	}

	/**
	 * Opens a form for one operation.
	 *
	 * @param string $op Operation.
	 */
	private function form_open( string $op ): void {
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" class="ss-inline-form">';
		echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION ) . '"><input type="hidden" name="op" value="' . esc_attr( $op ) . '">';
		echo '<input type="hidden" name="back" value="' . esc_attr( self::url() ) . '">';
		wp_nonce_field( self::ACTION );
	}

	/**
	 * Current password field.
	 */
	private function password_field(): void {
		echo '<label>' . esc_html__( 'Current password:', 'sentinel-shield' ) . ' <input type="password" name="password" autocomplete="current-password" required></label> ';
	}

	/**
	 * Logs a two-factor change.
	 *
	 * @param string   $event  Event type.
	 * @param \WP_User $user   Account changed.
	 * @param string   $reason Description.
	 */
	private function log( string $event, \WP_User $user, string $reason ): void {
		$this->c->get( EventRepository::class )->log(
			$event,
			array(
				'ip'      => (string) $this->c->get( 'client_ip' ),
				'module'  => 'two_factor',
				'reason'  => $reason,
				'user_id' => (int) $user->ID,
				'context' => array(
					'user' => $user->user_login,
					'by'   => get_current_user_id(),
				),
			)
		);
	}

	/**
	 * Settings.
	 */
	private function settings(): Settings {
		return $this->c->get( Settings::class );
	}

	/**
	 * Per-user methods.
	 */
	private function users(): UserTwoFactor {
		return $this->c->get( UserTwoFactor::class );
	}

	/**
	 * Login flow.
	 */
	private function login(): TwoFactorLogin {
		return $this->c->get( TwoFactorLogin::class );
	}
}
