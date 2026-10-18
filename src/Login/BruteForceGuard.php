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
use SentinelShield\Support\Mutex;
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
	public const LOCK_WAIT     = 1;

	/**
	 * WordPress's credential checks, skipped for logins refused at admission.
	 */
	private const CREDENTIAL_CHECKS = array( 'wp_authenticate_username_password', 'wp_authenticate_email_password', 'wp_authenticate_application_password' );

	/**
	 * IPs locked out during this request.
	 *
	 * @var array<string, true>
	 */
	private array $locked = array();

	/**
	 * Name of the per-IP login lock this request holds, if any.
	 *
	 * @var string|null
	 */
	private ?string $held = null;

	/**
	 * Credential checks taken off `authenticate` for the current call: callback => priority.
	 *
	 * @var array<string, int>
	 */
	private array $suspended = array();

	/**
	 * Name admitted by admit() in the current `authenticate` call, so the final
	 * check does not repeat the same queries.
	 *
	 * @var string|null
	 */
	private ?string $admitted = null;

	/**
	 * Refusal of the current REST request's application password, if any.
	 *
	 * @var \WP_Error|null
	 */
	private ?\WP_Error $rest_denied = null;

	/**
	 * Credential errors that count as a guess (others, such as application
	 * passwords being switched off, do not).
	 */
	private const GUESS_ERRORS = array( 'invalid_username', 'invalid_email', 'incorrect_password' );

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
		add_filter( 'authenticate', array( $this, 'admit' ), 1, 3 );
		add_filter( 'authenticate', array( $this, 'authenticate' ), 95, 3 );
		add_action( 'wp_authenticate_application_password_errors', array( $this, 'application_password' ), 10, 2 );
		// REST API Basic authentication checks application passwords outside `authenticate`.
		add_filter( 'determine_current_user', array( $this, 'rest_admit' ), 19 );
		add_action( 'application_password_failed_authentication', array( $this, 'application_password_failed' ) );
		add_filter( 'rest_authentication_errors', array( $this, 'rest_error' ), 5 );
		add_action( 'wp_login_failed', array( $this, 'failed' ), 10, 2 );
		add_action( 'wp_login', array( $this, 'succeeded' ), 10, 2 );
		add_action( 'shutdown', array( $this, 'release' ) );
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
		// Locked out in this request, or by a parallel request after this one
		// passed the firewall (its counter was reset by that lockout).
		if ( isset( $this->locked[ $ip ] ) || ( $current && $this->gate->is_blocked_now( $ip ) ) ) {
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
	 * `authenticate` filter, first: refuses logins over a limit before WordPress
	 * checks the password, so a refused login costs no password hashing. Also
	 * takes the per-IP lock, which then covers the password check until the
	 * result is counted.
	 *
	 * @param \WP_User|\WP_Error|null $user     Result so far.
	 * @param string                  $username Submitted name or email.
	 * @param string                  $password Submitted password (unused).
	 * @return \WP_User|\WP_Error|null
	 */
	public function admit( $user, $username = '', $password = '' ) {
		unset( $password );
		$username = is_string( $username ) ? $username : '';
		if ( '' === $username || $user instanceof \WP_User ) {
			return $user;
		}
		$denied = $this->deny_if_needed( $username );
		if ( null === $denied ) {
			$this->admitted = $username;
			return $user;
		}
		$this->suspend_credential_checks();
		return $denied;
	}

	/**
	 * Takes WordPress's password checks off this `authenticate` call; they are
	 * put back at the end of it (resume_credential_checks()).
	 */
	private function suspend_credential_checks(): void {
		foreach ( self::CREDENTIAL_CHECKS as $callback ) {
			$priority = has_filter( 'authenticate', $callback );
			if ( false !== $priority ) {
				remove_filter( 'authenticate', $callback, (int) $priority );
				$this->suspended[ $callback ] = (int) $priority;
			}
		}
		add_filter( 'authenticate', array( $this, 'resume_credential_checks' ), PHP_INT_MAX );
	}

	/**
	 * `authenticate` filter, last: restores the password checks for the next
	 * login in the same request (an XML-RPC multicall can hold many).
	 *
	 * @param \WP_User|\WP_Error|null $user Result.
	 * @return \WP_User|\WP_Error|null
	 */
	public function resume_credential_checks( $user ) {
		foreach ( $this->suspended as $callback => $priority ) {
			add_filter( 'authenticate', $callback, $priority, 3 );
		}
		$this->suspended = array();
		remove_filter( 'authenticate', array( $this, 'resume_credential_checks' ), PHP_INT_MAX );
		return $user;
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
		if ( $this->admitted === $username ) {
			// Checked at admission a moment ago; nothing was counted since.
			$this->admitted = null;
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
	 * `determine_current_user`, just before WordPress validates an application
	 * password sent with HTTP Basic authentication (REST API): applies the same
	 * limits as the login form, before any password hashing. A refused request
	 * stays logged out and gets a 429 error.
	 *
	 * @param int|false $user_id User found so far.
	 * @return int|false
	 */
	public function rest_admit( $user_id ) {
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- Compared as a login name only.
		$name = isset( $_SERVER['PHP_AUTH_USER'] ) && is_string( $_SERVER['PHP_AUTH_USER'] ) ? (string) wp_unslash( $_SERVER['PHP_AUTH_USER'] ) : '';
		if ( $user_id || '' === $name || null !== $this->rest_denied ) {
			return $user_id;
		}
		$denied = $this->deny_if_needed( $name );
		if ( null !== $denied ) {
			$this->rest_denied = new \WP_Error( self::ERROR_CODE, wp_strip_all_tags( $denied->get_error_message() ), array( 'status' => 429 ) );
			remove_filter( 'determine_current_user', 'wp_validate_application_password', 20 );
		}
		return $user_id;
	}

	/**
	 * `rest_authentication_errors`: reports a refused application password.
	 *
	 * @param \WP_Error|true|null $result Result so far.
	 * @return \WP_Error|true|null
	 */
	public function rest_error( $result ) {
		return null === $this->rest_denied || is_wp_error( $result ) ? $result : $this->rest_denied;
	}

	/**
	 * `application_password_failed_authentication`: counts a wrong application
	 * password sent to the REST API. During the normal login flow (XML-RPC,
	 * login forms) `wp_login_failed` counts it instead, so it is not counted twice.
	 *
	 * @param \WP_Error $error Why it failed.
	 */
	public function application_password_failed( $error ): void {
		if ( doing_filter( 'authenticate' ) || ! $error instanceof \WP_Error || ! array_intersect( $error->get_error_codes(), self::GUESS_ERRORS ) ) {
			return;
		}
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- Compared as a login name only.
		$name = isset( $_SERVER['PHP_AUTH_USER'] ) && is_string( $_SERVER['PHP_AUTH_USER'] ) ? (string) wp_unslash( $_SERVER['PHP_AUTH_USER'] ) : '';
		$this->failed( $name, $error );
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
		try {
			$this->record_failure( $username, $error );
		} finally {
			$this->release();
		}
	}

	/**
	 * Counts a failure and locks out over the limit.
	 *
	 * @param mixed $username Submitted name.
	 * @param mixed $error    Why it failed.
	 */
	private function record_failure( $username, $error ): void {
		// Refusals by this plugin are not password guesses.
		if ( $error instanceof \WP_Error && array_intersect( $error->get_error_codes(), array( self::ERROR_CODE, LoginGeoGuard::ERROR_CODE, TwoFactorLogin::ERROR_API, TwoFactorLogin::ERROR_SETUP, TwoFactorLogin::ERROR_LIMIT ) ) ) {
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
				$count = $this->attempts->count_account( $account, $since, true );
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
		$this->release();
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
		return ! ( $current && ( $this->ip_fallback )() ) && $this->gate->is_protected( $ip, true );
	}

	/**
	 * Checks the current request; logs and returns an error when refused.
	 *
	 * @param string $username Submitted name.
	 */
	private function deny_if_needed( string $username ): ?\WP_Error {
		$ip = (string) ( $this->ip )();
		if ( ! $this->serialize( $ip ) && ! $this->settings->is_test_mode( 'login_guard' ) ) {
			return new \WP_Error( self::ERROR_CODE, __( '<strong>Error:</strong> Another login from your IP address is in progress. Please try again.', 'sentinel-shield' ) );
		}
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
	 * Lets one login per IP run at a time, from the limit check until the
	 * failure is counted (or the request ends), so parallel requests cannot all
	 * pass the check before any of their failures are recorded. A request that
	 * has to wait more than a few seconds is refused (not counted as a failure),
	 * so a flood cannot tie up PHP workers.
	 *
	 * @param string $ip Client IP.
	 * @return bool False when another login from the IP holds the lock.
	 */
	private function serialize( string $ip ): bool {
		$bin = IpAddress::to_binary( $ip );
		if ( null === $bin || $this->is_protected( (string) IpAddress::from_binary( $bin ), true ) ) {
			return true;
		}
		$name = 'login_ip_' . bin2hex( $bin );
		if ( Mutex::holds( $name ) ) {
			return true;
		}
		if ( ! Mutex::acquire( $name, self::LOCK_WAIT ) ) {
			return false;
		}
		$this->held = Mutex::holds( $name ) ? $name : null;
		return true;
	}

	/**
	 * Releases the per-IP login lock (after the attempt is counted, on success,
	 * or when the request ends).
	 */
	public function release(): void {
		if ( null !== $this->held ) {
			Mutex::release( $this->held );
			$this->held = null;
		}
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
			// Only the IP's counter is reset: its failures still count against the
			// account, so a distributed attack cannot launder them through lockouts.
			$this->attempts->reset_ip_counter( $bin );
			if ( ! $lockout->is_test ) {
				$this->locked[ $ip ] = true;
			}
			return;
		}
		if ( Throttle::once( 'login_limit_' . md5( $ip ), $this->window_minutes() * MINUTE_IN_SECONDS ) ) {
			$test = $this->settings->is_test_mode( 'login_guard' );
			$why  = $this->gate->is_protected( $ip )
				? __( 'the address is allowlisted or belongs to this server, so it is never blocked; requests reach it like this when a trusted proxy does not name the visitor', 'sentinel-shield' )
				: __( 'progressive lockouts are off', 'sentinel-shield' );
			/* translators: 1: reason, 2: why the IP is not locked out. */
			$this->log( 'login_limit', $ip, '', sprintf( __( '%1$s. Logins from this IP are refused until the failures age out (%2$s).', 'sentinel-shield' ), $reason, $why ), $test );
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
