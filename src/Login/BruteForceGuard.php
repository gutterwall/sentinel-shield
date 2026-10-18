<?php
/**
 * Login brute-force protection.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Login;

use SentinelShield\Firewall\Gate;
use SentinelShield\Geo\LoginGeoGuard;
use SentinelShield\Http\Request;
use SentinelShield\Lockout\Lockout;
use SentinelShield\Net\IpAddress;
use SentinelShield\Repository\EventRepository;
use SentinelShield\Repository\LoginAttemptRepository;
use SentinelShield\Settings;
use SentinelShield\Support\Throttle;
use SentinelShield\TwoFactor\TwoFactorLogin;

defined( 'ABSPATH' ) || exit;

/**
 * Two limits, both counted over a sliding window:
 *
 * - Per IP: too many failed logins from one IP lock it out through the
 *   progressive lockouts (15 min, 1 h, 24 h, permanent by default). The login
 *   is also refused on the spot, so an XML-RPC multicall cannot try hundreds of
 *   passwords in one request.
 * - Per account: too many failures against one account from any number of IPs
 *   (a distributed attack) refuse password logins to it, except from IPs that
 *   logged in to it successfully before and allowlisted IPs, until the
 *   failures age out. No IP is locked out for this.
 *
 * Refusals do not depend on the password, so they reveal nothing about it.
 * Allowlisted IPs and this server are never counted or refused.
 */
final class BruteForceGuard {

	public const ERROR_CODE    = 'sentinel_shield_too_many';
	public const ERROR_INVALID = 'sentinel_shield_invalid_login';
	public const KNOWN_IPS     = '_sentinel_shield_known_ips';
	public const KNOWN_MAX     = 10;

	/**
	 * IPs locked out during this request.
	 *
	 * @var array<string, true>
	 */
	private array $locked = array();

	/**
	 * Time source.
	 *
	 * @var \Closure
	 */
	private \Closure $clock;

	/**
	 * Constructor.
	 *
	 * @param Settings               $settings    Settings.
	 * @param LoginAttemptRepository $attempts    Failure history.
	 * @param Gate                   $gate        For allowlist checks.
	 * @param EventRepository        $events      Event log.
	 * @param \Closure               $ip          Returns the client IP.
	 * @param \Closure               $ip_fallback Returns true when the IP is a trusted proxy's own.
	 * @param \Closure               $lockout     fn( string $ip, string $module, string $reason ): ?Lockout.
	 * @param \Closure|null          $clock       fn(): int.
	 */
	public function __construct(
		private Settings $settings,
		private LoginAttemptRepository $attempts,
		private Gate $gate,
		private EventRepository $events,
		private \Closure $ip,
		private \Closure $ip_fallback,
		private \Closure $lockout,
		?\Closure $clock = null
	) {
		$this->clock = $clock ?? static fn(): int => time();
	}

	/**
	 * Hooks the checks.
	 */
	public function register(): void {
		add_filter( 'authenticate', array( $this, 'authenticate' ), 95, 3 );
		add_action( 'wp_authenticate_application_password_errors', array( $this, 'application_password' ), 10, 2 );
		add_action( 'wp_login_failed', array( $this, 'failed' ), 10, 2 );
		add_action( 'wp_login', array( $this, 'succeeded' ), 10, 2 );
		if ( $this->settings->get( 'login.generic_errors', true ) ) {
			add_filter( 'authenticate', array( $this, 'generic_error' ), 100 );
		}
		if ( $this->settings->get( 'login.disable_xmlrpc', false ) ) {
			add_filter( 'xmlrpc_enabled', '__return_false' );
		}
		add_filter(
			'shake_error_codes',
			static function ( array $codes ): array {
				return array_merge( $codes, array( self::ERROR_CODE, self::ERROR_INVALID ) );
			}
		);
	}

	/**
	 * Whether a login attempt from an IP for a name would be refused now.
	 *
	 * @param string $ip       IP address.
	 * @param string $username Submitted name or email ('' to check the IP only).
	 * @param bool   $current  Whether $ip is the current request's client IP.
	 * @return array{allowed:bool, reason:string}
	 */
	public function check( string $ip, string $username = '', bool $current = false ): array {
		$bin = IpAddress::to_binary( $ip );
		if ( null === $bin ) {
			return self::result( true, 'invalid' );
		}
		$ip = (string) IpAddress::from_binary( $bin );
		if ( $this->is_protected( $ip, $current ) ) {
			return self::result( true, 'allowlist' );
		}
		if ( isset( $this->locked[ $ip ] ) ) {
			return self::result( false, 'ip_limit' );
		}
		$since = $this->since();
		if ( $this->attempts->count_ip( $bin, $since ) >= $this->max_failures() ) {
			return self::result( false, 'ip_limit' );
		}
		$account_max = (int) $this->settings->get( 'login.account_max_failures', 20 );
		if ( $account_max > 0 && '' !== $username && $this->attempts->count_account( self::account_key( $username ), $since )['failures'] >= $account_max ) {
			$user = LoginGeoGuard::find_account( $username );
			if ( null !== $user && self::is_known_ip( $user, $ip ) ) {
				return self::result( true, 'known_ip' );
			}
			return self::result( false, 'account_limit' );
		}
		return self::result( true, 'ok' );
	}

	/**
	 * `authenticate` filter: refuses logins over a limit, whatever the password.
	 *
	 * @param \WP_User|\WP_Error|null $user     Result so far.
	 * @param string                  $username Submitted name or email.
	 * @param string                  $password Submitted password (unused).
	 * @return \WP_User|\WP_Error|null
	 */
	public function authenticate( $user, $username = '', $password = '' ) {
		unset( $password );
		$username = is_string( $username ) ? $username : '';
		if ( '' === $username ) {
			// Nothing submitted (or an existing login cookie being checked).
			return $user;
		}
		$denied = $this->deny_if_needed( $username );
		return null === $denied ? $user : $denied;
	}

	/**
	 * Application password (REST API / XML-RPC) check.
	 *
	 * @param \WP_Error $error Errors so far; adding one rejects the request.
	 * @param \WP_User  $user  Account.
	 */
	public function application_password( $error, $user ): void {
		if ( ! $error instanceof \WP_Error || ! $user instanceof \WP_User ) {
			return;
		}
		$denied = $this->deny_if_needed( (string) $user->user_login );
		if ( null !== $denied ) {
			$error->add( self::ERROR_CODE, $denied->get_error_message() );
		}
	}

	/**
	 * Replaces "unknown username" and "wrong password" with one message, so the
	 * login form does not reveal which accounts exist.
	 *
	 * @param \WP_User|\WP_Error|null $user Result so far.
	 * @return \WP_User|\WP_Error|null
	 */
	public function generic_error( $user ) {
		if ( $user instanceof \WP_Error && array_intersect( $user->get_error_codes(), array( 'invalid_username', 'invalid_email', 'incorrect_password' ) ) ) {
			return new \WP_Error(
				self::ERROR_INVALID,
				__( '<strong>Error:</strong> The username, email address or password is incorrect.', 'sentinel-shield' )
				. ' <a href="' . esc_url( wp_lostpassword_url() ) . '">' . __( 'Lost your password?', 'sentinel-shield' ) . '</a>'
			);
		}
		return $user;
	}

	/**
	 * `wp_login_failed`: counts the failure and locks out over the limit.
	 *
	 * @param string         $username Submitted name.
	 * @param \WP_Error|null $error    Why it failed.
	 */
	public function failed( $username, $error = null ): void {
		// Refusals by this plugin are not password guesses.
		if ( $error instanceof \WP_Error && array_intersect( $error->get_error_codes(), array( self::ERROR_CODE, LoginGeoGuard::ERROR_CODE, TwoFactorLogin::ERROR_API ) ) ) {
			return;
		}
		$ip  = (string) ( $this->ip )();
		$bin = IpAddress::to_binary( $ip );
		if ( null === $bin || $this->is_protected( $ip, true ) ) {
			return;
		}
		$ip       = (string) IpAddress::from_binary( $bin );
		$username = is_string( $username ) ? $username : '';
		$account  = self::account_key( $username );
		$now      = ( $this->clock )();
		$this->attempts->record( $bin, $account, $now );

		$name = strtolower( trim( $username ) );
		if ( '' !== $name && str_starts_with( $account, 'n:' ) && in_array( $name, self::instant_usernames( $this->settings ), true ) ) {
			/* translators: %s: username. */
			$this->lock( $ip, sprintf( __( 'Tried to log in as "%s", a username on the instant lockout list', 'sentinel-shield' ), sanitize_user( $username ) ) );
			return;
		}

		$since    = $this->since();
		$failures = $this->attempts->count_ip( $bin, $since );
		$max      = $this->max_failures();
		if ( $failures >= $max ) {
			/* translators: 1: number of failures, 2: minutes. */
			$this->lock( $ip, sprintf( __( '%1$d failed logins within %2$d minutes', 'sentinel-shield' ), $failures, $this->window_minutes() ) );
		}

		$account_max = (int) $this->settings->get( 'login.account_max_failures', 20 );
		if ( $account_max > 0 && '' !== $username ) {
			$count = $this->attempts->count_account( $account, $since );
			if ( $count['failures'] >= $account_max && Throttle::once( 'login_account_' . md5( $account ), $this->window_minutes() * MINUTE_IN_SECONDS ) ) {
				$this->log(
					'account_attack',
					$ip,
					$username,
					/* translators: 1: username, 2: number of failures, 3: number of IPs, 4: minutes. */
					sprintf( __( 'Account "%1$s": %2$d failed logins from %3$d IPs within %4$d minutes. Password logins to it are limited to IPs it logged in from before until the failures age out.', 'sentinel-shield' ), sanitize_user( $username ), $count['failures'], $count['ips'], $this->window_minutes() ),
					false
				);
			}
		}
	}

	/**
	 * `wp_login`: remembers the IP as one this account logs in from.
	 *
	 * @param string   $login Login name.
	 * @param \WP_User $user  Account.
	 */
	public function succeeded( $login, $user = null ): void {
		unset( $login );
		$ip = IpAddress::normalize( (string) ( $this->ip )() );
		if ( ! $user instanceof \WP_User || null === $ip || '' === $ip || ( $this->ip_fallback )() ) {
			return;
		}
		$known        = self::known_ips( $user );
		$known[ $ip ] = ( $this->clock )();
		arsort( $known );
		update_user_meta( $user->ID, self::KNOWN_IPS, array_slice( $known, 0, self::KNOWN_MAX, true ) );
	}

	/**
	 * Human-readable explanation of a check result.
	 *
	 * @param array{allowed:bool, reason:string} $check Result.
	 */
	public static function explain( array $check ): string {
		$texts = array(
			'invalid'       => __( 'Not checked: not a valid IP.', 'sentinel-shield' ),
			'allowlist'     => __( 'Allowed: the IP is on the allowlist or belongs to this server.', 'sentinel-shield' ),
			'ok'            => __( 'Allowed: under the limits.', 'sentinel-shield' ),
			'known_ip'      => __( 'Allowed: the account is over its limit, but this IP logged in to it before.', 'sentinel-shield' ),
			'ip_limit'      => __( 'Refused: too many failed logins from this IP.', 'sentinel-shield' ),
			'account_limit' => __( 'Refused: too many failed logins to this account from different IPs.', 'sentinel-shield' ),
		);
		return $texts[ $check['reason'] ] ?? $check['reason'];
	}

	/**
	 * Key that failures against a submitted name are counted under.
	 *
	 * @param string $username Submitted name or email.
	 */
	public static function account_key( string $username ): string {
		$user = '' === $username ? null : LoginGeoGuard::find_account( $username );
		if ( null !== $user ) {
			return 'u:' . $user->ID;
		}
		return 'n:' . mb_substr( mb_strtolower( trim( $username ) ), 0, 60 );
	}

	/**
	 * Readable form of an account key.
	 *
	 * @param string $key Account key.
	 */
	public static function account_label( string $key ): string {
		if ( str_starts_with( $key, 'u:' ) ) {
			$user = get_userdata( (int) substr( $key, 2 ) );
			return $user instanceof \WP_User ? $user->user_login : $key;
		}
		/* translators: %s: name that matches no account. */
		return sprintf( __( '%s (no such account)', 'sentinel-shield' ), substr( $key, 2 ) );
	}

	/**
	 * Names on the instant lockout list, lower case.
	 *
	 * @param Settings $settings Settings.
	 * @return list<string>
	 */
	public static function instant_usernames( Settings $settings ): array {
		$names = preg_split( '/[\s,]+/', strtolower( (string) $settings->get( 'login.instant_usernames', '' ) ), -1, PREG_SPLIT_NO_EMPTY );
		return array_values( array_unique( (array) $names ) );
	}

	/**
	 * IPs an account logged in from, newest first.
	 *
	 * @param \WP_User $user Account.
	 * @return array<string, int> IP => Unix time.
	 */
	public static function known_ips( \WP_User $user ): array {
		$known = get_user_meta( $user->ID, self::KNOWN_IPS, true );
		if ( ! is_array( $known ) ) {
			return array();
		}
		$cutoff = time() - 90 * DAY_IN_SECONDS;
		return array_filter( array_map( 'intval', $known ), static fn( int $t ): bool => $t >= $cutoff );
	}

	/**
	 * Whether an account logged in from an IP before.
	 *
	 * @param \WP_User $user Account.
	 * @param string   $ip   Normalized IP.
	 */
	public static function is_known_ip( \WP_User $user, string $ip ): bool {
		return isset( self::known_ips( $user )[ $ip ] );
	}

	/**
	 * Failures from one IP that trigger a lockout.
	 */
	public function max_failures(): int {
		return max( 1, (int) $this->settings->get( 'login.max_failures', 5 ) );
	}

	/**
	 * Counting window in minutes.
	 */
	public function window_minutes(): int {
		return max( 1, (int) $this->settings->get( 'login.window_minutes', 15 ) );
	}

	/**
	 * Start of the counting window.
	 */
	private function since(): int {
		return ( $this->clock )() - $this->window_minutes() * MINUTE_IN_SECONDS;
	}

	/**
	 * Whether an IP is allowlisted or this server's.
	 *
	 * @param string $ip      Normalized IP.
	 * @param bool   $current Whether it is the current request's client IP.
	 */
	private function is_protected( string $ip, bool $current ): bool {
		// A request that fell back to a proxy's own IP must not inherit the proxy's allowlist entry.
		return ! ( $current && ( $this->ip_fallback )() ) && $this->gate->is_protected( $ip );
	}

	/**
	 * Checks the current request; logs and returns an error when refused.
	 *
	 * @param string $username Submitted name.
	 */
	private function deny_if_needed( string $username ): ?\WP_Error {
		$ip    = (string) ( $this->ip )();
		$check = $this->check( $ip, $username, true );
		if ( $check['allowed'] ) {
			return null;
		}
		$test = $this->settings->is_test_mode( 'login_guard' );
		if ( Throttle::once_within_budget( 'login_guard_' . md5( $ip . '|' . $check['reason'] ), MINUTE_IN_SECONDS, 'login_guard_all', 60, MINUTE_IN_SECONDS ) ) {
			/* translators: 1: explanation, 2: username. */
			$this->log( $test ? 'would_deny_login' : 'login_denied', $ip, $username, sprintf( __( '%1$s Login as: %2$s', 'sentinel-shield' ), self::explain( $check ), sanitize_user( $username ) ), $test );
		}
		if ( $test ) {
			return null;
		}
		return new \WP_Error( self::ERROR_CODE, __( '<strong>Error:</strong> Too many failed login attempts. Please try again later.', 'sentinel-shield' ) );
	}

	/**
	 * Locks out an IP; without the lockout module the per-IP count keeps
	 * refusing logins until the failures age out.
	 *
	 * @param string $ip     IP.
	 * @param string $reason Reason.
	 */
	private function lock( string $ip, string $reason ): void {
		$lockout = ( $this->lockout )( $ip, 'login_guard', $reason );
		$bin     = (string) IpAddress::to_binary( $ip );
		if ( $lockout instanceof Lockout ) {
			// The block takes over; the next lockout needs a fresh run of failures.
			$this->attempts->clear_ip( $bin );
			if ( ! $lockout->is_test ) {
				$this->locked[ $ip ] = true;
			}
			return;
		}
		if ( Throttle::once( 'login_limit_' . md5( $ip ), $this->window_minutes() * MINUTE_IN_SECONDS ) ) {
			$test = $this->settings->is_test_mode( 'login_guard' );
			/* translators: %s: reason. */
			$this->log( 'login_limit', $ip, '', sprintf( __( '%s. Logins from this IP are refused until the failures age out (progressive lockouts are off).', 'sentinel-shield' ), $reason ), $test );
		}
	}

	/**
	 * Logs an event.
	 *
	 * @param string $event    Event type.
	 * @param string $ip       IP.
	 * @param string $username Submitted name.
	 * @param string $reason   Description.
	 * @param bool   $test     Test mode.
	 */
	private function log( string $event, string $ip, string $username, string $reason, bool $test ): void {
		$user = '' === $username ? null : LoginGeoGuard::find_account( $username );
		$this->events->log(
			$event,
			array(
				'ip'         => $ip,
				'module'     => 'login_guard',
				'reason'     => mb_substr( $reason, 0, 255 ),
				'uri'        => Request::uri(),
				'user_agent' => Request::user_agent(),
				'user_id'    => null === $user ? 0 : $user->ID,
				'is_test'    => $test,
				'context'    => array( 'user' => sanitize_user( $username ) ),
			)
		);
	}

	/**
	 * Check result.
	 *
	 * @param bool   $allowed Allowed.
	 * @param string $reason  Reason key.
	 * @return array{allowed:bool, reason:string}
	 */
	private static function result( bool $allowed, string $reason ): array {
		return array(
			'allowed' => $allowed,
			'reason'  => $reason,
		);
	}
}
