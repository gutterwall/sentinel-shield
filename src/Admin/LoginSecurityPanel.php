<?php
/**
 * Status panel on the Login Security settings tab.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Admin;

use SentinelShield\Container;
use SentinelShield\Lockdown\AdminRegistry;
use SentinelShield\Login\AppPasswordPolicy;
use SentinelShield\Login\BruteForceGuard;
use SentinelShield\Repository\LoginAttemptRepository;
use SentinelShield\Settings;
use SentinelShield\TwoFactor\TwoFactorLogin;
use SentinelShield\TwoFactor\UserTwoFactor;
use SentinelShield\Support\Cached;

defined( 'ABSPATH' ) || exit;

/**
 * Failed logins in the last 24 hours (by IP and by account) and the
 * two-factor status of every administrator-level account.
 */
final class LoginSecurityPanel {

	/**
	 * Constructor.
	 *
	 * @param Container $c Services.
	 */
	public function __construct( private Container $c ) {}

	/**
	 * Renders the panel.
	 */
	public function render(): void {
		$settings = $this->c->get( Settings::class );
		$attempts = $this->c->get( LoginAttemptRepository::class );
		$guard    = $this->c->get( BruteForceGuard::class );
		$since    = time() - DAY_IN_SECONDS;

		echo '<div class="ss-card"><h2>' . esc_html__( 'Failed logins', 'sentinel-shield' ) . '</h2>';
		if ( ! $settings->is_enabled() || ! $settings->is_module_enabled( 'login_guard' ) ) {
			echo '<div class="notice notice-warning inline"><p>' . esc_html__( 'The "Login brute-force protection" module (or protection as a whole) is off on the Modules tab, so failed logins are not counted or limited.', 'sentinel-shield' ) . '</p></div>';
		} elseif ( $settings->is_test_mode( 'login_guard' ) ) {
			echo '<div class="notice notice-info inline"><p>' . esc_html__( 'Brute-force protection is in test mode: logins over a limit are allowed and logged as "would deny login", and lockouts are logged as "would lock out".', 'sentinel-shield' ) . '</p></div>';
		}
		if ( ! $settings->is_module_enabled( 'lockout' ) ) {
			echo '<div class="notice notice-warning inline"><p>' . esc_html__( 'The Progressive lockouts module is off: IPs over the limit cannot log in until their failures age out, but they are not blocked from the rest of the site.', 'sentinel-shield' ) . '</p></div>';
		}
		$total = (int) Cached::remember( 'login_total', MINUTE_IN_SECONDS, fn(): int => $attempts->count_since( $since ) );
		/* translators: 1: number of failed logins, 2: failures per IP, 3: minutes. */
		echo '<p class="ss-big">' . esc_html( sprintf( __( '%1$s failed logins in the last 24 hours. Limit: %2$d per IP within %3$d minutes.', 'sentinel-shield' ), number_format_i18n( $total ), $guard->max_failures(), $guard->window_minutes() ) ) . '</p>';

		$ips = (array) Cached::remember( 'login_top_ips', MINUTE_IN_SECONDS, fn(): array => $attempts->top_ips( $since ) );
		if ( $ips ) {
			echo '<h3>' . esc_html__( 'IPs with the most failed logins (24 hours)', 'sentinel-shield' ) . '</h3><table class="widefat striped ss-narrow"><thead><tr><th>' . esc_html__( 'IP', 'sentinel-shield' ) . '</th><th>' . esc_html__( 'Failures', 'sentinel-shield' ) . '</th><th>' . esc_html__( 'Accounts tried', 'sentinel-shield' ) . '</th><th>' . esc_html__( 'Last', 'sentinel-shield' ) . '</th><th>' . esc_html__( 'Login now', 'sentinel-shield' ) . '</th></tr></thead><tbody>';
			foreach ( $ips as $row ) {
				$check = $guard->check( $row['ip'] );
				echo '<tr><td><code>' . esc_html( $row['ip'] ) . '</code></td><td>' . esc_html( (string) $row['failures'] ) . '</td><td>' . esc_html( (string) $row['accounts'] ) . '</td><td>' . esc_html( View::time( $row['last'] ) ) . '</td><td>' . View::pill( $check['allowed'] ? __( 'Allowed', 'sentinel-shield' ) : __( 'Refused', 'sentinel-shield' ), $check['allowed'] ? 'ok' : 'bad' ) . '</td></tr>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- pill() escapes.
			}
			echo '</tbody></table>';
			echo '<p class="description">' . esc_html__( 'IPs that were locked out appear on the IP Rules page. A lockout restarts the IP\'s own limit, but its failures still count against the accounts it tried. Figures here may be up to a minute old.', 'sentinel-shield' ) . '</p>';
		}
		$accounts = (array) Cached::remember( 'login_top_accounts', MINUTE_IN_SECONDS, fn(): array => $attempts->top_accounts( $since ) );
		if ( $accounts ) {
			$account_max = (int) $settings->get( 'login.account_max_failures', 20 );
			$window      = $attempts->top_accounts( time() - $guard->window_minutes() * MINUTE_IN_SECONDS, 100 );
			$current     = array_column( $window, 'failures', 'account' );
			echo '<h3>' . esc_html__( 'Accounts with the most failed logins (24 hours)', 'sentinel-shield' ) . '</h3><table class="widefat striped ss-narrow"><thead><tr><th>' . esc_html__( 'Account', 'sentinel-shield' ) . '</th><th>' . esc_html__( 'Failures', 'sentinel-shield' ) . '</th><th>' . esc_html__( 'From IPs', 'sentinel-shield' ) . '</th><th>' . esc_html__( 'Last', 'sentinel-shield' ) . '</th><th>' . esc_html__( 'Status', 'sentinel-shield' ) . '</th></tr></thead><tbody>';
			foreach ( $accounts as $row ) {
				$limited = $account_max > 0 && (int) ( $current[ $row['account'] ] ?? 0 ) >= $account_max;
				echo '<tr><td>' . esc_html( BruteForceGuard::account_label( $row['account'] ) ) . '</td><td>' . esc_html( (string) $row['failures'] ) . '</td><td>' . esc_html( (string) $row['ips'] ) . '</td><td>' . esc_html( View::time( $row['last'] ) ) . '</td><td>' . ( $limited ? View::pill( __( 'Known IPs only', 'sentinel-shield' ), 'warn' ) : View::pill( __( 'Normal', 'sentinel-shield' ), 'ok' ) ) . '</td></tr>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- pill() escapes.
			}
			echo '</tbody></table>';
		}
		if ( $total > 0 ) {
			View::form_open( 'login_security' );
			echo '<input type="hidden" name="op" value="clear">';
			submit_button( __( 'Forget all failed logins', 'sentinel-shield' ), 'secondary', 'submit', false );
			echo ' <span class="description">' . esc_html__( 'Resets every count, e.g. after you locked yourself out by mistyping. Lockouts already applied stay on the IP Rules page.', 'sentinel-shield' ) . '</span></form>';
		}
		echo '</div>';

		$this->two_factor( $settings );
		$this->app_passwords( $settings );
	}

	/**
	 * Application passwords of privileged accounts, with their policy status.
	 *
	 * @param Settings $settings Settings.
	 */
	private function app_passwords( Settings $settings ): void {
		if ( ! class_exists( '\WP_Application_Passwords' ) ) {
			return;
		}
		$labels = array(
			'ok'      => array( __( 'Active', 'sentinel-shield' ), 'ok' ),
			'expired' => array( __( 'Expired', 'sentinel-shield' ), 'info' ),
			'unused'  => array( __( 'Retired (unused)', 'sentinel-shield' ), 'info' ),
			'blocked' => array( __( 'Blocked by policy', 'sentinel-shield' ), 'info' ),
		);
		$mode   = (string) $settings->get( 'login.app_passwords', 'all' );
		$rows   = '';
		foreach ( $this->c->get( AdminRegistry::class )->privileged_users() as $row ) {
			$user = get_userdata( (int) $row['id'] );
			if ( ! $user instanceof \WP_User ) {
				continue;
			}
			foreach ( \WP_Application_Passwords::get_user_application_passwords( $user->ID ) as $item ) {
				$state = 'all' !== $mode ? 'blocked' : AppPasswordPolicy::status( $item, $settings );
				$used  = empty( $item['last_used'] ) ? __( 'never', 'sentinel-shield' ) : wp_date( 'Y-m-d', (int) $item['last_used'] ) . ( empty( $item['last_ip'] ) ? '' : ' (' . $item['last_ip'] . ')' );
				$rows .= '<tr><td>' . esc_html( $user->user_login ) . '</td><td>' . esc_html( (string) $item['name'] ) . '</td><td>' . esc_html( wp_date( 'Y-m-d', (int) $item['created'] ) ) . '</td><td>' . esc_html( $used ) . '</td><td>' . View::pill( $labels[ $state ][0], $labels[ $state ][1] ) . '</td></tr>';
			}
		}
		echo '<div class="ss-card"><h2>' . esc_html__( 'Application passwords of administrator-level accounts', 'sentinel-shield' ) . '</h2>';
		echo '<p>' . esc_html__( 'These skip two-factor authentication by design. Delete any nobody recognizes from the account\'s profile, and use the policy settings above to retire old or unused ones automatically.', 'sentinel-shield' ) . '</p>';
		if ( '' === $rows ) {
			echo '<p class="description">' . esc_html__( 'None.', 'sentinel-shield' ) . '</p></div>';
			return;
		}
		echo '<table class="widefat striped ss-narrow"><thead><tr><th>' . esc_html__( 'Account', 'sentinel-shield' ) . '</th><th>' . esc_html__( 'Name', 'sentinel-shield' ) . '</th><th>' . esc_html__( 'Created', 'sentinel-shield' ) . '</th><th>' . esc_html__( 'Last used', 'sentinel-shield' ) . '</th><th>' . esc_html__( 'Status', 'sentinel-shield' ) . '</th></tr></thead><tbody>' . $rows . '</tbody></table></div>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Rows escaped above; pill() escapes.
	}

	/**
	 * Two-factor status of administrator-level accounts.
	 *
	 * @param Settings $settings Settings.
	 */
	private function two_factor( Settings $settings ): void {
		$users = $this->c->get( UserTwoFactor::class );
		$login = $this->c->get( TwoFactorLogin::class );
		echo '<div class="ss-card"><h2>' . esc_html__( 'Two-factor authentication', 'sentinel-shield' ) . '</h2>';
		if ( ! $settings->is_enabled() || ! $settings->is_module_enabled( 'two_factor' ) ) {
			echo '<div class="notice notice-warning inline"><p>' . esc_html__( 'The "Two-factor authentication" module (or protection as a whole) is off on the Modules tab, so nobody is asked for a code.', 'sentinel-shield' ) . '</p></div>';
		}
		echo '<p>' . esc_html__( 'Each user sets up their own methods under Users → Two-Factor Authentication. To reset a user who lost their phone, tick "Reset two-factor authentication" on their profile, or run wp sentinel 2fa <user> --reset.', 'sentinel-shield' ) . ' <a href="' . esc_url( TwoFactorPage::url() ) . '">' . esc_html__( 'Set up your own', 'sentinel-shield' ) . '</a></p>';
		echo '<h3>' . esc_html__( 'Administrator-level accounts', 'sentinel-shield' ) . '</h3><table class="widefat striped ss-narrow"><thead><tr><th>' . esc_html__( 'Account', 'sentinel-shield' ) . '</th><th>' . esc_html__( 'Authenticator app', 'sentinel-shield' ) . '</th><th>' . esc_html__( 'Email codes', 'sentinel-shield' ) . '</th><th>' . esc_html__( 'Backup codes', 'sentinel-shield' ) . '</th><th>' . esc_html__( 'At login', 'sentinel-shield' ) . '</th></tr></thead><tbody>';
		$stuck = array();
		$rows  = '';
		foreach ( $this->c->get( AdminRegistry::class )->privileged_users() as $row ) {
			$user = get_userdata( (int) $row['id'] );
			if ( ! $user instanceof \WP_User ) {
				continue;
			}
			$summary = $users->summary( (int) $user->ID );
			$asked   = $login->needs_second_step( $user );
			if ( $login->locked_out( $user ) ) {
				$stuck[] = $user->user_login;
				$pill    = View::pill( __( 'Cannot log in', 'sentinel-shield' ), 'bad' );
			} else {
				$pill = $asked ? View::pill( __( 'Code asked', 'sentinel-shield' ), 'ok' ) : View::pill( __( 'Password only', 'sentinel-shield' ), 'warn' );
			}
			$app   = $summary['totp'] ? ( $summary['totp_readable'] ? __( 'Yes', 'sentinel-shield' ) : __( 'Unreadable', 'sentinel-shield' ) ) : __( 'No', 'sentinel-shield' );
			$rows .= '<tr><td>' . esc_html( $user->user_login ) . '</td><td>' . esc_html( $app ) . '</td><td>' . esc_html( $summary['email'] ? __( 'Yes', 'sentinel-shield' ) : __( 'No', 'sentinel-shield' ) ) . '</td><td>' . esc_html( (string) $summary['backup'] ) . '</td><td>' . $pill . '</td></tr>';
		}
		echo $rows . '</tbody></table>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped above; pill() escapes.
		if ( $stuck ) {
			/* translators: %s: list of usernames. */
			echo '<div class="notice notice-error inline"><p>' . esc_html( sprintf( __( 'These accounts must use two-factor authentication but have no way to get a code, so their logins are refused: %s. Allow email codes, or have them set up an authenticator app before requiring it.', 'sentinel-shield' ), implode( ', ', $stuck ) ) ) . '</p></div>';
		}
		echo '</div>';
	}
}
