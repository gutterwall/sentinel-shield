<?php
/**
 * The second login step: asks for an authenticator, email or backup code.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\TwoFactor;

use SentinelShield\Http\Request;
use SentinelShield\Lockdown\AdminRegistry;
use SentinelShield\Repository\EventRepository;
use SentinelShield\Settings;
use SentinelShield\Support\Mutex;
use SentinelShield\Support\Throttle;

defined( 'ABSPATH' ) || exit;

/**
 * Runs last on `authenticate`: when the password was right and the account uses
 * two-factor authentication, no login cookie is set. Instead a random,
 * single-use token (hashed in user meta, 10 minutes, five tries) is put in an
 * HttpOnly cookie and the browser goes to wp-login.php?action=sentinel_shield_2fa.
 * Only a correct code there sets the login cookie and fires `wp_login`.
 *
 * Password logins over XML-RPC and the REST API cannot show the second step and
 * are refused for these accounts; application passwords keep working, since they
 * are separate secrets created by a logged-in user. Each wrong code counts as a
 * failed login for the brute-force protection.
 */
final class TwoFactorLogin {

	public const ACTION        = 'sentinel_shield_2fa';
	public const COOKIE        = 'sentinel_shield_2fa';
	public const TRUST_COOKIE  = 'sentinel_shield_2fa_trust_';
	public const ERROR_API     = 'sentinel_shield_2fa_api';
	public const ERROR_WRONG   = 'sentinel_shield_2fa_failed';
	public const ERROR_SETUP   = 'sentinel_shield_2fa_setup';
	public const LOGIN_TIMEOUT = 600;
	public const MAX_TRIES     = 5;
	public const EMAIL_MAX     = 5;
	public const EMAIL_GAP     = 60;
	public const LOCK_WAIT     = 10;

	/**
	 * Redirects and stops: fn( string $url ): never.
	 *
	 * @var \Closure
	 */
	private \Closure $redirect;

	/**
	 * Time source.
	 *
	 * @var \Closure
	 */
	private \Closure $clock;

	/**
	 * Constructor.
	 *
	 * @param Settings        $settings Settings.
	 * @param UserTwoFactor   $users    Per-user methods.
	 * @param SecretBox       $box      Keys for hashes and cookies.
	 * @param EventRepository $events   Event log.
	 * @param \Closure        $ip       Returns the client IP.
	 * @param \Closure|null   $redirect fn( string $url ): never; defaults to wp_safe_redirect() + exit.
	 * @param \Closure|null   $clock    fn(): int.
	 */
	public function __construct(
		private Settings $settings,
		private UserTwoFactor $users,
		private SecretBox $box,
		private EventRepository $events,
		private \Closure $ip,
		?\Closure $redirect = null,
		?\Closure $clock = null
	) {
		$this->redirect = $redirect ?? static function ( string $url ): never {
			wp_safe_redirect( $url );
			exit;
		};
		$this->clock    = $clock ?? static fn(): int => time();
	}

	/**
	 * Hooks the login step.
	 */
	public function register(): void {
		add_filter( 'authenticate', array( $this, 'authenticate' ), 9999, 3 );
		add_action( 'login_form_' . self::ACTION, array( $this, 'screen' ) );
		add_filter(
			'shake_error_codes',
			static function ( array $codes ): array {
				$codes[] = self::ERROR_WRONG;
				return $codes;
			}
		);
	}

	/**
	 * Whether two-factor authentication is required for an account.
	 *
	 * @param \WP_User $user Account.
	 */
	public function required( \WP_User $user ): bool {
		$required = (string) $this->settings->get( 'twofa.required', 'none' );
		return 'all' === $required || ( 'privileged' === $required && AdminRegistry::is_privileged( $user ) );
	}

	/**
	 * Whether the site allows email codes.
	 */
	public function email_allowed(): bool {
		return (bool) $this->settings->get( 'twofa.email', true );
	}

	/**
	 * The ways an account can pass the second step right now.
	 *
	 * @param \WP_User $user Account.
	 * @return list<string> Any of totp, email, backup.
	 */
	public function methods( \WP_User $user ): array {
		$id      = (int) $user->ID;
		$totp    = $this->users->has_totp( $id );
		$methods = array();
		if ( $totp && null !== $this->users->totp_secret( $id ) ) {
			$methods[] = 'totp';
		}
		// Required accounts without an app get emailed codes until they set one up.
		if ( $this->email_allowed() && ( $this->users->email_enabled( $id ) || ( $this->required( $user ) && ! $totp ) ) ) {
			$methods[] = 'email';
		}
		if ( ( $totp || $methods ) && $this->users->backup_remaining( $id ) > 0 ) {
			$methods[] = 'backup';
		}
		return $methods;
	}

	/**
	 * Whether a login by this account needs the second step. Accounts that are
	 * required to use it always do, and so does an authenticator app whose
	 * secret cannot be read: when no method is left, the login is refused
	 * rather than allowed with the password alone.
	 *
	 * @param \WP_User $user Account.
	 */
	public function needs_second_step( \WP_User $user ): bool {
		return $this->required( $user ) || $this->users->has_totp( (int) $user->ID ) || array() !== $this->methods( $user );
	}

	/**
	 * Whether an account needs the second step but has no way to pass it
	 * (required with email codes off and no app, or an unreadable app secret
	 * with nothing else). Such logins are refused.
	 *
	 * @param \WP_User $user Account.
	 */
	public function locked_out( \WP_User $user ): bool {
		return $this->needs_second_step( $user ) && array() === $this->methods( $user );
	}

	/**
	 * Whether an account is required to use two-factor authentication but has
	 * no method of its own set up.
	 *
	 * @param \WP_User $user Account.
	 */
	public function setup_missing( \WP_User $user ): bool {
		$id = (int) $user->ID;
		return $this->required( $user ) && ! $this->users->has_totp( $id ) && ! ( $this->email_allowed() && $this->users->email_enabled( $id ) );
	}

	/**
	 * `authenticate` filter: intercepts correct passwords of two-factor accounts.
	 *
	 * @param \WP_User|\WP_Error|null $user     Result so far.
	 * @param string                  $username Submitted name (unused).
	 * @param string                  $password Submitted password (unused).
	 * @return \WP_User|\WP_Error|null
	 */
	public function authenticate( $user, $username = '', $password = '' ) {
		unset( $username, $password );
		if ( ! $user instanceof \WP_User || did_action( 'application_password_did_authenticate' ) || ! $this->needs_second_step( $user ) ) {
			return $user;
		}
		if ( $this->locked_out( $user ) ) {
			if ( Throttle::once( 'twofa_no_method_' . $user->ID, MINUTE_IN_SECONDS ) ) {
				$this->log( 'twofa_no_method', $user, __( 'Login refused: two-factor authentication is needed but the account has no usable method', 'sentinel-shield' ) );
			}
			return new \WP_Error( self::ERROR_SETUP, __( '<strong>Error:</strong> This account must use two-factor authentication but has no way to receive a code. Ask a site administrator for help.', 'sentinel-shield' ) );
		}
		if ( ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) || ( defined( 'REST_REQUEST' ) && REST_REQUEST ) || wp_is_json_request() ) {
			return new \WP_Error( self::ERROR_API, __( 'This account uses two-factor authentication. Use an application password for XML-RPC and the REST API.', 'sentinel-shield' ) );
		}
		if ( $this->trusted_browser( $user ) ) {
			return $user;
		}
		// phpcs:disable WordPress.Security.NonceVerification.Missing, WordPress.Security.NonceVerification.Recommended -- Login form fields; WordPress's login form has no nonce.
		$redirect = isset( $_REQUEST['redirect_to'] ) ? esc_url_raw( wp_unslash( (string) $_REQUEST['redirect_to'] ) ) : '';
		$remember = ! empty( $_POST['rememberme'] );
		$interim  = ! empty( $_REQUEST['interim-login'] );
		// phpcs:enable
		$token = $this->begin( $user, $redirect, $remember, $interim );
		$this->set_cookie( self::COOKIE, $user->ID . '|' . $token, 0 );
		( $this->redirect )( $this->screen_url( $interim ) );
	}

	/**
	 * Starts the second step: stores the pending login and, when email is the
	 * only way in, sends the first code.
	 *
	 * @param \WP_User $user     Account.
	 * @param string   $redirect Where to go afterwards.
	 * @param bool     $remember "Remember me" was ticked.
	 * @param bool     $interim  Session-expired login popup.
	 * @return string Token for the cookie.
	 */
	public function begin( \WP_User $user, string $redirect = '', bool $remember = false, bool $interim = false ): string {
		$token = bin2hex( random_bytes( 32 ) );
		$this->save_pending(
			(int) $user->ID,
			array(
				'hash'     => hash( 'sha256', $token ),
				'expires'  => ( $this->clock )() + self::LOGIN_TIMEOUT,
				'redirect' => $redirect,
				'remember' => $remember,
				'interim'  => $interim,
				'tries'    => 0,
				'email'    => '',
				'email_at' => array(),
			)
		);
		$methods = $this->methods( $user );
		if ( ! in_array( 'totp', $methods, true ) && in_array( 'email', $methods, true ) ) {
			$this->send_email_code( $user, $token );
		}
		return $token;
	}

	/**
	 * The pending login for a token, or null when missing, wrong or expired.
	 *
	 * @param int    $user_id User.
	 * @param string $token   Token from the cookie.
	 * @return array<string, mixed>|null
	 */
	public function pending( int $user_id, string $token ): ?array {
		$pending = get_user_meta( $user_id, UserTwoFactor::META . 'login', true );
		if ( ! is_array( $pending ) || '' === $token || ! hash_equals( (string) ( $pending['hash'] ?? '' ), hash( 'sha256', $token ) ) ) {
			return null;
		}
		if ( (int) ( $pending['expires'] ?? 0 ) < ( $this->clock )() ) {
			delete_user_meta( $user_id, UserTwoFactor::META . 'login' );
			return null;
		}
		return $pending;
	}

	/**
	 * Emails a new 8-digit code (at most five per login, one a minute).
	 *
	 * @param \WP_User $user  Account.
	 * @param string   $token Pending login token.
	 * @return true|\WP_Error
	 */
	public function send_email_code( \WP_User $user, string $token ): bool|\WP_Error {
		return Mutex::run(
			self::lock_name( (int) $user->ID ),
			self::LOCK_WAIT,
			fn() => $this->send_email_code_locked( $user, $token ),
			new \WP_Error( 'sentinel_shield_2fa_email', __( 'The site is busy. Please try again.', 'sentinel-shield' ) )
		);
	}

	/**
	 * Sends the code while holding the account's lock (see send_email_code()).
	 *
	 * @param \WP_User $user  Account.
	 * @param string   $token Pending login token.
	 * @return true|\WP_Error
	 */
	private function send_email_code_locked( \WP_User $user, string $token ): bool|\WP_Error {
		self::refresh( (int) $user->ID );
		$pending = $this->pending( (int) $user->ID, $token );
		if ( null === $pending || ! in_array( 'email', $this->methods( $user ), true ) ) {
			return new \WP_Error( 'sentinel_shield_2fa_email', __( 'Email codes are not available for this login.', 'sentinel-shield' ) );
		}
		$now  = ( $this->clock )();
		$sent = array_map( 'intval', (array) $pending['email_at'] );
		if ( count( $sent ) >= self::EMAIL_MAX ) {
			return new \WP_Error( 'sentinel_shield_2fa_email', __( 'Too many codes were emailed for this login. Please log in again.', 'sentinel-shield' ) );
		}
		if ( $sent && $now - max( $sent ) < self::EMAIL_GAP ) {
			return new \WP_Error( 'sentinel_shield_2fa_email', __( 'A code was emailed less than a minute ago. Please wait before asking for another.', 'sentinel-shield' ) );
		}
		$code                = str_pad( (string) random_int( 0, 99999999 ), 8, '0', STR_PAD_LEFT );
		$pending['email']    = BackupCodes::hash( $code, $this->box->hash_key() );
		$pending['email_at'] = array_merge( $sent, array( $now ) );
		$this->save_pending( (int) $user->ID, $pending );

		$site = wp_specialchars_decode( (string) get_bloginfo( 'name' ), ENT_QUOTES );
		/* translators: %s: site name. */
		$subject = sprintf( __( '[%s] Your login code', 'sentinel-shield' ), $site );
		$body    = sprintf(
			/* translators: 1: user login, 2: site name, 3: code, 4: IP address. */
			__( "Hello %1\$s,\n\nYour code for logging in to %2\$s is:\n\n%3\$s\n\nIt is valid for 10 minutes. The login was started from IP address %4\$s.\n\nIf this was not you, someone knows your password: change it now.", 'sentinel-shield' ),
			$user->user_login,
			$site,
			substr( $code, 0, 4 ) . ' ' . substr( $code, 4 ),
			(string) ( $this->ip )()
		);
		if ( ! wp_mail( $user->user_email, $subject, $body ) ) {
			return new \WP_Error( 'sentinel_shield_2fa_email', __( 'The code could not be emailed. Use your authenticator app or a backup code, or contact the site administrator.', 'sentinel-shield' ) );
		}
		return true;
	}

	/**
	 * Checks a submitted code.
	 *
	 * @param \WP_User $user  Account.
	 * @param string   $token Pending login token.
	 * @param string   $code  Submitted code.
	 * @return array{result:string, method:string} result is ok, wrong, too_many, expired or busy.
	 */
	public function attempt( \WP_User $user, string $token, string $code ): array {
		// One check at a time per account, so parallel requests cannot share the
		// five tries or use the same one-time code twice.
		return Mutex::run(
			self::lock_name( (int) $user->ID ),
			self::LOCK_WAIT,
			fn(): array => $this->attempt_locked( $user, $token, $code ),
			array(
				'result' => 'busy',
				'method' => '',
			)
		);
	}

	/**
	 * Checks the code while holding the account's lock (see attempt()).
	 *
	 * @param \WP_User $user  Account.
	 * @param string   $token Pending login token.
	 * @param string   $code  Submitted code.
	 * @return array{result:string, method:string}
	 */
	private function attempt_locked( \WP_User $user, string $token, string $code ): array {
		$id = (int) $user->ID;
		self::refresh( $id );
		$pending = $this->pending( $id, $token );
		if ( null === $pending ) {
			return array(
				'result' => 'expired',
				'method' => '',
			);
		}
		$methods = $this->methods( $user );
		$now     = ( $this->clock )();
		$digits  = (string) preg_replace( '/\s+/', '', $code );
		$method  = '';
		if ( in_array( 'totp', $methods, true ) && $this->users->verify_totp( $id, $digits, $now ) ) {
			$method = 'totp';
		} elseif ( in_array( 'email', $methods, true ) && '' !== $pending['email'] && preg_match( '/^\d{8}$/', $digits ) && hash_equals( (string) $pending['email'], BackupCodes::hash( $digits, $this->box->hash_key() ) ) ) {
			$method = 'email';
		} elseif ( in_array( 'backup', $methods, true ) && $this->users->use_backup_code( $id, $code ) ) {
			$method = 'backup';
		}

		if ( '' !== $method ) {
			delete_user_meta( $id, UserTwoFactor::META . 'login' );
			if ( 'backup' === $method ) {
				$this->log(
					'twofa_backup_used',
					$user,
					/* translators: %d: number of codes left. */
					sprintf( __( 'Backup code used; %d left', 'sentinel-shield' ), $this->users->backup_remaining( $id ) )
				);
			}
			return array(
				'result' => 'ok',
				'method' => $method,
			);
		}

		$pending['tries'] = (int) $pending['tries'] + 1;
		// Counts toward the brute-force limits like a wrong password.
		$wrong = new \WP_Error( self::ERROR_WRONG, __( 'Invalid authentication code.', 'sentinel-shield' ) );
		do_action( 'wp_login_failed', $user->user_login, $wrong ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Core hook.
		if ( $pending['tries'] >= self::MAX_TRIES ) {
			delete_user_meta( $id, UserTwoFactor::META . 'login' );
			/* translators: %d: number of tries. */
			$this->log( 'twofa_failed', $user, sprintf( __( '%d wrong two-factor codes after a correct password; the login was cancelled', 'sentinel-shield' ), self::MAX_TRIES ) );
			return array(
				'result' => 'too_many',
				'method' => '',
			);
		}
		$this->save_pending( $id, $pending );
		return array(
			'result' => 'wrong',
			'method' => '',
		);
	}

	/**
	 * Whether this browser was trusted by the account within the trust period.
	 *
	 * @param \WP_User $user Account.
	 */
	public function trusted_browser( \WP_User $user ): bool {
		$days = (int) $this->settings->get( 'twofa.remember_days', 0 );
		$name = $this->trust_cookie_name( (int) $user->ID );
		if ( $days <= 0 || empty( $_COOKIE[ $name ] ) ) {
			return false;
		}
		$parts = explode( '|', sanitize_text_field( wp_unslash( (string) $_COOKIE[ $name ] ) ) );
		if ( 2 !== count( $parts ) || (int) $parts[0] < ( $this->clock )() ) {
			return false;
		}
		return hash_equals( $this->trust_mac( (int) $user->ID, (int) $parts[0] ), $parts[1] );
	}

	/**
	 * Cookie value marking this browser as trusted until a time.
	 *
	 * @param int $user_id User.
	 * @param int $expires Unix time.
	 */
	public function trust_value( int $user_id, int $expires ): string {
		return $expires . '|' . $this->trust_mac( $user_id, $expires );
	}

	/**
	 * Name of an account's trusted-browser cookie (does not reveal the user ID).
	 *
	 * @param int $user_id User.
	 */
	public function trust_cookie_name( int $user_id ): string {
		return self::TRUST_COOKIE . substr( hash_hmac( 'sha256', 'name|' . $user_id, $this->box->hash_key() ), 0, 16 );
	}

	/**
	 * The second-step page (wp-login.php?action=sentinel_shield_2fa).
	 */
	public function screen(): void {
		nocache_headers();
		[ $user, $token ] = $this->from_cookie();
		$pending          = null === $user ? null : $this->pending( (int) $user->ID, $token );
		if ( null === $user || null === $pending ) {
			$this->set_cookie( self::COOKIE, '', 1 );
			$this->page_message( __( 'This login has expired or is no longer valid. Please log in again.', 'sentinel-shield' ) );
		}
		$methods = $this->methods( $user );
		$notice  = '';
		$error   = null;
		// phpcs:disable WordPress.Security.NonceVerification.Missing -- The pending-login token in the HttpOnly cookie ties the form to this login.
		if ( 'POST' === Request::method() ) {
			if ( isset( $_POST['sentinel_shield_send_email'] ) ) {
				$sent = $this->send_email_code( $user, $token );
				if ( is_wp_error( $sent ) ) {
					$error = $sent;
				} else {
					$notice = __( 'A code has been emailed to you.', 'sentinel-shield' );
				}
			} else {
				$code   = isset( $_POST['sentinel_shield_code'] ) ? sanitize_text_field( wp_unslash( (string) $_POST['sentinel_shield_code'] ) ) : '';
				$result = $this->attempt( $user, $token, $code );
				if ( 'ok' === $result['result'] ) {
					$this->complete( $user, $pending, ! empty( $_POST['sentinel_shield_trust'] ) );
				}
				if ( 'too_many' === $result['result'] || 'expired' === $result['result'] ) {
					$this->set_cookie( self::COOKIE, '', 1 );
					$this->page_message(
						'too_many' === $result['result']
							? __( 'Too many incorrect codes. Please log in again.', 'sentinel-shield' )
							: __( 'This login has expired or is no longer valid. Please log in again.', 'sentinel-shield' )
					);
				}
				$error = 'busy' === $result['result']
					? new \WP_Error( self::ERROR_WRONG, __( '<strong>Error:</strong> The site is busy. Please enter the code again.', 'sentinel-shield' ) )
					: new \WP_Error( self::ERROR_WRONG, __( '<strong>Error:</strong> The code is not correct, or it was already used.', 'sentinel-shield' ) );
			}
		}
		// phpcs:enable
		$this->render_form( $user, $methods, $pending, $notice, $error );
		exit;
	}

	/**
	 * Sets the login cookie, fires `wp_login` and redirects (or shows the
	 * popup's success page).
	 *
	 * @param \WP_User             $user    Account.
	 * @param array<string, mixed> $pending Pending login.
	 * @param bool                 $trust   Trust this browser.
	 */
	private function complete( \WP_User $user, array $pending, bool $trust ): never {
		$this->set_cookie( self::COOKIE, '', 1 );
		$days = (int) $this->settings->get( 'twofa.remember_days', 0 );
		if ( $trust && $days > 0 ) {
			$expires = ( $this->clock )() + $days * DAY_IN_SECONDS;
			$this->set_cookie( $this->trust_cookie_name( (int) $user->ID ), $this->trust_value( (int) $user->ID, $expires ), $expires );
		}
		wp_set_auth_cookie( (int) $user->ID, (bool) $pending['remember'] );
		/** This action is documented in wp-includes/user.php */
		do_action( 'wp_login', $user->user_login, $user ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Core hook.

		if ( ! empty( $pending['interim'] ) ) {
			$GLOBALS['interim_login'] = 'success'; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited -- Read by login_header() for the session-expired popup.
			login_header( '', '<p class="message">' . esc_html__( 'You have logged in successfully.', 'sentinel-shield' ) . '</p>' );
			echo '</div>';
			/** This action is documented in wp-login.php */
			do_action( 'login_footer' ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Core hook.
			echo '</body></html>';
			exit;
		}

		$requested = (string) $pending['redirect'];
		$redirect  = apply_filters( 'login_redirect', '' === $requested ? admin_url() : $requested, $requested, $user ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Core hook.
		if ( empty( $redirect ) || 'wp-admin/' === $redirect || admin_url() === $redirect ) {
			if ( is_multisite() && ! get_active_blog_for_user( $user->ID ) && ! is_super_admin( $user->ID ) ) {
				$redirect = user_admin_url();
			} elseif ( is_multisite() && ! $user->has_cap( 'read' ) ) {
				$redirect = get_dashboard_url( $user->ID );
			} elseif ( ! $user->has_cap( 'edit_posts' ) ) {
				$redirect = $user->has_cap( 'read' ) ? admin_url( 'profile.php' ) : home_url();
			}
		}
		( $this->redirect )( (string) $redirect );
	}

	/**
	 * The code form.
	 *
	 * @param \WP_User             $user    Account.
	 * @param list<string>         $methods Available methods.
	 * @param array<string, mixed> $pending Pending login.
	 * @param string               $notice  Message.
	 * @param \WP_Error|null       $error   Error.
	 */
	private function render_form( \WP_User $user, array $methods, array $pending, string $notice, ?\WP_Error $error ): void {
		$lines = array();
		if ( in_array( 'totp', $methods, true ) ) {
			$lines[] = __( 'Enter the 6-digit code from your authenticator app.', 'sentinel-shield' );
		}
		if ( in_array( 'email', $methods, true ) ) {
			$lines[] = $pending['email_at']
				/* translators: %s: masked email address. */
				? sprintf( __( 'A code was emailed to %s.', 'sentinel-shield' ), self::mask_email( (string) $user->user_email ) )
				: __( 'You can have a code emailed to you.', 'sentinel-shield' );
		}
		if ( in_array( 'backup', $methods, true ) ) {
			$lines[] = __( 'You can also use one of your backup codes.', 'sentinel-shield' );
		}
		if ( ! $methods ) {
			$lines[] = __( 'Your authenticator app can no longer be checked because this site\'s security keys changed, and no other method is available. Ask an administrator to reset two-factor authentication for your account.', 'sentinel-shield' );
		}
		$message = '<p class="message">' . implode( '<br>', array_map( 'esc_html', $lines ) ) . '</p>';
		if ( '' !== $notice ) {
			$message .= '<p class="message">' . esc_html( $notice ) . '</p>';
		}
		login_header( __( 'Two-factor authentication', 'sentinel-shield' ), $message, $error );
		$action = $this->screen_url( ! empty( $pending['interim'] ) );
		if ( $methods ) {
			echo '<form name="sentinel_shield_2fa" id="loginform" action="' . esc_url( $action ) . '" method="post" autocomplete="off">';
			echo '<p><label for="sentinel-shield-code">' . esc_html__( 'Authentication code', 'sentinel-shield' ) . '</label>';
			echo '<input type="text" name="sentinel_shield_code" id="sentinel-shield-code" class="input" value="" size="20" autocomplete="one-time-code" autocapitalize="off" spellcheck="false" required autofocus></p>';
			$days = (int) $this->settings->get( 'twofa.remember_days', 0 );
			if ( $days > 0 ) {
				/* translators: %d: number of days. */
				echo '<p class="forgetmenot"><input name="sentinel_shield_trust" type="checkbox" id="sentinel-shield-trust" value="1"> <label for="sentinel-shield-trust">' . esc_html( sprintf( _n( 'Trust this browser for %d day', 'Trust this browser for %d days', $days, 'sentinel-shield' ), $days ) ) . '</label></p>';
			}
			echo '<p class="submit"><input type="submit" class="button button-primary button-large" value="' . esc_attr__( 'Verify', 'sentinel-shield' ) . '"></p>';
			echo '</form>';
			if ( in_array( 'email', $methods, true ) ) {
				echo '<form action="' . esc_url( $action ) . '" method="post" style="margin-top:12px;text-align:center">';
				echo '<input type="submit" class="button" name="sentinel_shield_send_email" value="' . esc_attr( $pending['email_at'] ? __( 'Email me a new code', 'sentinel-shield' ) : __( 'Email me a code', 'sentinel-shield' ) ) . '">';
				echo '</form>';
			}
		}
		echo '<p id="nav"><a href="' . esc_url( wp_login_url() ) . '">' . esc_html__( 'Cancel and log in again', 'sentinel-shield' ) . '</a></p>';
		login_footer( 'sentinel-shield-code' );
	}

	/**
	 * A one-message login page, then stop.
	 *
	 * @param string $text Message.
	 */
	private function page_message( string $text ): never {
		login_header( __( 'Two-factor authentication', 'sentinel-shield' ), '', new \WP_Error( 'sentinel_shield_2fa', esc_html( $text ) ) );
		echo '<p id="nav"><a href="' . esc_url( wp_login_url() ) . '">' . esc_html__( 'Log in', 'sentinel-shield' ) . '</a></p>';
		login_footer();
		exit;
	}

	/**
	 * Reads the pending-login cookie.
	 *
	 * @return array{0:\WP_User|null, 1:string}
	 */
	private function from_cookie(): array {
		$raw   = isset( $_COOKIE[ self::COOKIE ] ) ? sanitize_text_field( wp_unslash( (string) $_COOKIE[ self::COOKIE ] ) ) : '';
		$parts = explode( '|', $raw );
		if ( 2 !== count( $parts ) || ! ctype_digit( $parts[0] ) || ! preg_match( '/^[0-9a-f]{64}$/', $parts[1] ) ) {
			return array( null, '' );
		}
		$user = get_userdata( (int) $parts[0] );
		return array( $user instanceof \WP_User ? $user : null, $parts[1] );
	}

	/**
	 * URL of the second-step page.
	 *
	 * @param bool $interim Session-expired popup.
	 */
	private function screen_url( bool $interim ): string {
		$args = array( 'action' => self::ACTION );
		if ( $interim ) {
			$args['interim-login'] = '1';
		}
		return add_query_arg( $args, wp_login_url() );
	}

	/**
	 * Stores the pending login.
	 *
	 * @param int                  $user_id User.
	 * @param array<string, mixed> $pending Data.
	 */
	private function save_pending( int $user_id, array $pending ): void {
		update_user_meta( $user_id, UserTwoFactor::META . 'login', $pending );
	}

	/**
	 * MAC for the trusted-browser cookie, tied to the account's device version.
	 *
	 * @param int $user_id User.
	 * @param int $expires Unix time.
	 */
	private function trust_mac( int $user_id, int $expires ): string {
		return hash_hmac( 'sha256', $user_id . '|' . $expires . '|' . $this->users->device_version( $user_id ), $this->box->hash_key() );
	}

	/**
	 * Sets or clears an HttpOnly cookie for the login page.
	 *
	 * @param string $name    Name.
	 * @param string $value   Value ('' to clear).
	 * @param int    $expires Unix time; 0 = browser session, 1 = delete.
	 */
	private function set_cookie( string $name, string $value, int $expires ): void {
		if ( '' === $value && 1 === $expires ) {
			unset( $_COOKIE[ $name ] );
		}
		if ( headers_sent() ) {
			return;
		}
		setcookie(
			$name,
			$value,
			array(
				'expires'  => $expires,
				'path'     => SITECOOKIEPATH,
				'domain'   => (string) COOKIE_DOMAIN,
				'secure'   => is_ssl(),
				'httponly' => true,
				'samesite' => 'Lax',
			)
		);
	}

	/**
	 * Name of an account's two-factor lock.
	 *
	 * @param int $user_id User.
	 */
	private static function lock_name( int $user_id ): string {
		return 'twofa_' . $user_id;
	}

	/**
	 * Drops cached user meta so values written by another request are seen.
	 *
	 * @param int $user_id User.
	 */
	private static function refresh( int $user_id ): void {
		wp_cache_delete( $user_id, 'user_meta' );
	}

	/**
	 * Logs an event about an account.
	 *
	 * @param string   $event  Event type.
	 * @param \WP_User $user   Account.
	 * @param string   $reason Description.
	 */
	private function log( string $event, \WP_User $user, string $reason ): void {
		$this->events->log(
			$event,
			array(
				'ip'         => (string) ( $this->ip )(),
				'module'     => 'two_factor',
				'reason'     => $reason,
				'uri'        => Request::uri(),
				'user_agent' => Request::user_agent(),
				'user_id'    => (int) $user->ID,
				'context'    => array( 'user' => $user->user_login ),
			)
		);
	}

	/**
	 * Partly hidden email address, e.g. j***@example.com.
	 *
	 * @param string $email Address.
	 */
	public static function mask_email( string $email ): string {
		$at = strpos( $email, '@' );
		if ( false === $at || 0 === $at ) {
			return '***';
		}
		return substr( $email, 0, 1 ) . str_repeat( '*', max( 3, $at - 1 ) ) . substr( $email, $at );
	}
}
