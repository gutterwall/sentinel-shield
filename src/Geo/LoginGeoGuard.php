<?php
/**
 * Restricts logins by the visitor's country.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Geo;

use SentinelShield\Firewall\Gate;
use SentinelShield\Http\Request;
use SentinelShield\Lockdown\AdminRegistry;
use SentinelShield\Net\IpAddress;
use SentinelShield\Repository\EventRepository;
use SentinelShield\Settings;
use SentinelShield\Support\Throttle;

defined( 'ABSPATH' ) || exit;

/**
 * Runs on `authenticate` at a late priority, so it covers wp-login.php, XML-RPC
 * and anything else using wp_authenticate(), plus application passwords (REST
 * API). The decision depends only on the IP and the account named, never on
 * whether the password was right, and a denial always replaces the password
 * result: a visitor from a denied country cannot use the login form to test
 * passwords. Allowlisted IPs and this server are never denied. Existing login
 * sessions are not affected.
 */
final class LoginGeoGuard {

	public const ERROR_CODE = 'sentinel_shield_geo_denied';

	/**
	 * Constructor.
	 *
	 * @param Settings        $settings    Settings.
	 * @param GeoResolver     $resolver    Country lookup.
	 * @param Gate            $gate        For allowlist checks.
	 * @param EventRepository $events      Event log.
	 * @param \Closure        $ip          Returns the current client IP.
	 * @param \Closure        $ip_fallback Returns true when the IP is a trusted proxy's own.
	 */
	public function __construct(
		private Settings $settings,
		private GeoResolver $resolver,
		private Gate $gate,
		private EventRepository $events,
		private \Closure $ip,
		private \Closure $ip_fallback
	) {}

	/**
	 * Hooks the checks.
	 */
	public function register(): void {
		add_filter( 'authenticate', array( $this, 'authenticate' ), 99, 3 );
		add_action( 'wp_authenticate_application_password_errors', array( $this, 'application_password' ), 10, 2 );
	}

	/**
	 * The login check.
	 *
	 * @param \WP_User|\WP_Error|null $user     Result so far.
	 * @param string                  $username Submitted username or email.
	 * @param string                  $password Submitted password (unused).
	 * @return \WP_User|\WP_Error|null
	 */
	public function authenticate( $user, $username, $password ) {
		unset( $password );
		$username = is_string( $username ) ? $username : '';
		if ( ! $user instanceof \WP_User && '' === $username ) {
			return $user;
		}
		$account = $user instanceof \WP_User ? $user : self::find_account( $username );
		$error   = $this->deny_if_needed( $account, $username );
		return null === $error ? $user : $error;
	}

	/**
	 * Application password (REST API / XML-RPC basic auth) check.
	 *
	 * @param \WP_Error $error Errors so far; adding one rejects the request.
	 * @param \WP_User  $user  Account.
	 */
	public function application_password( $error, $user ): void {
		if ( ! $error instanceof \WP_Error || ! $user instanceof \WP_User ) {
			return;
		}
		$denied = $this->deny_if_needed( $user, (string) $user->user_login );
		if ( null !== $denied ) {
			$error->add( self::ERROR_CODE, $denied->get_error_message() );
		}
	}

	/**
	 * Whether a login from an IP would be allowed.
	 *
	 * @param string        $ip      IP address.
	 * @param \WP_User|null $user    Account, if known.
	 * @param bool          $current Whether $ip is the current request's client IP.
	 * @return array{allowed:bool, country:string, source:string, reason:string}
	 */
	public function check( string $ip, ?\WP_User $user, bool $current = false ): array {
		$mode = (string) $this->settings->get( 'geo.mode', 'off' );
		$out  = array(
			'allowed' => true,
			'country' => '',
			'source'  => '',
			'reason'  => 'off',
		);
		if ( 'allow' !== $mode && 'block' !== $mode ) {
			return $out;
		}
		$countries = self::countries( $this->settings );
		if ( ! $countries ) {
			// "Allow only" with an empty list would deny everyone; treat it as not configured.
			$out['reason'] = 'no_countries';
			return $out;
		}
		if ( 'privileged' === $this->settings->get( 'geo.scope', 'all' ) && ( null === $user || ! AdminRegistry::is_privileged( $user ) ) ) {
			$out['reason'] = 'scope';
			return $out;
		}
		// A request that fell back to a proxy's own IP must not inherit the proxy's allowlist entry.
		// An unusable IP is not "protected" here: it falls under the unknown-country rule.
		if ( null !== IpAddress::to_binary( $ip ) && ! ( $current && ( $this->ip_fallback )() ) && $this->gate->is_protected( $ip ) ) {
			$out['reason'] = 'allowlist';
			return $out;
		}
		$geo            = $this->resolver->resolve( $ip, $current );
		$out['country'] = $geo['country'];
		$out['source']  = $geo['source'];
		if ( '' === $geo['country'] ) {
			$deny           = 'deny' === $this->settings->get( 'geo.unknown', 'allow' );
			$out['allowed'] = ! $deny;
			$out['reason']  = $deny ? 'unknown_denied' : 'unknown_allowed';
			return $out;
		}
		$listed         = in_array( $geo['country'], $countries, true );
		$out['allowed'] = 'allow' === $mode ? $listed : ! $listed;
		$out['reason']  = $out['allowed'] ? 'country_allowed' : 'country_denied';
		return $out;
	}

	/**
	 * Human-readable explanation of a check result.
	 *
	 * @param array{allowed:bool, country:string, source:string, reason:string} $check Result.
	 */
	public static function explain( array $check ): string {
		$where = '' === $check['country']
			? __( 'unknown country', 'sentinel-shield' )
			: CountryList::label( $check['country'] );
		$texts = array(
			'off'             => __( 'Login location restriction is off.', 'sentinel-shield' ),
			'no_countries'    => __( 'Not checked: no countries are listed.', 'sentinel-shield' ),
			'scope'           => __( 'Not checked: the restriction applies to administrator-level accounts only.', 'sentinel-shield' ),
			'allowlist'       => __( 'Allowed: the IP is on the allowlist or belongs to this server.', 'sentinel-shield' ),
			/* translators: %s: source name. */
			'unknown_allowed' => sprintf( __( 'Allowed: the country is unknown (%s) and unknown locations are allowed.', 'sentinel-shield' ), self::source_label( $check['source'] ) ),
			/* translators: %s: source name. */
			'unknown_denied'  => sprintf( __( 'Denied: the country is unknown (%s) and unknown locations are denied.', 'sentinel-shield' ), self::source_label( $check['source'] ) ),
			/* translators: 1: country, 2: source name. */
			'country_allowed' => sprintf( __( 'Allowed: %1$s, from %2$s.', 'sentinel-shield' ), $where, self::source_label( $check['source'] ) ),
			/* translators: 1: country, 2: source name. */
			'country_denied'  => sprintf( __( 'Denied: %1$s, from %2$s.', 'sentinel-shield' ), $where, self::source_label( $check['source'] ) ),
		);
		return $texts[ $check['reason'] ] ?? $check['reason'];
	}

	/**
	 * Name of a lookup source.
	 *
	 * @param string $source Source key.
	 */
	public static function source_label( string $source ): string {
		$labels = array(
			'cloudflare' => __( 'Cloudflare', 'sentinel-shield' ),
			'server'     => __( 'server variable', 'sentinel-shield' ),
			'dbip'       => __( 'DB-IP database', 'sentinel-shield' ),
			'private'    => __( 'private or local address', 'sentinel-shield' ),
			'invalid'    => __( 'not a valid IP', 'sentinel-shield' ),
			'none'       => __( 'no source knows this address', 'sentinel-shield' ),
		);
		return $labels[ $source ] ?? $source;
	}

	/**
	 * Configured country codes.
	 *
	 * @param Settings $settings Settings.
	 * @return list<string>
	 */
	public static function countries( Settings $settings ): array {
		return CountryList::parse( (string) $settings->get( 'geo.countries', '' ) )[0];
	}

	/**
	 * Finds the account a login names, by login or email.
	 *
	 * @param string $username Submitted name.
	 */
	public static function find_account( string $username ): ?\WP_User {
		$user = get_user_by( 'login', $username );
		if ( ! $user && is_email( $username ) ) {
			$user = get_user_by( 'email', $username );
		}
		return $user instanceof \WP_User ? $user : null;
	}

	/**
	 * Checks the current request; logs and returns an error when denied.
	 *
	 * @param \WP_User|null $account  Account named.
	 * @param string        $username Name as submitted.
	 */
	private function deny_if_needed( ?\WP_User $account, string $username ): ?\WP_Error {
		$ip    = (string) ( $this->ip )();
		$check = $this->check( $ip, $account, true );
		if ( $check['allowed'] ) {
			return null;
		}
		$test = $this->settings->is_test_mode( 'geo_login' );
		if ( Throttle::once_within_budget( 'geo_login_' . md5( $ip ), MINUTE_IN_SECONDS, 'geo_login_all', 60, MINUTE_IN_SECONDS ) ) {
			$this->events->log(
				$test ? 'would_deny_login' : 'login_denied',
				array(
					'ip'         => $ip,
					'module'     => 'geo_login',
					/* translators: 1: explanation, 2: username. */
					'reason'     => sprintf( __( '%1$s Login as: %2$s', 'sentinel-shield' ), self::explain( $check ), sanitize_user( $username ) ),
					'uri'        => Request::uri(),
					'user_agent' => Request::user_agent(),
					'user_id'    => null === $account ? 0 : $account->ID,
					'is_test'    => $test,
					'context'    => array(
						'country' => $check['country'],
						'source'  => $check['source'],
						'user'    => sanitize_user( $username ),
					),
				)
			);
		}
		if ( $test ) {
			return null;
		}
		$message = __( 'Logging in from your location is not allowed.', 'sentinel-shield' );
		if ( 'dbip' === $check['source'] ) {
			// DB-IP's licence (CC BY 4.0) asks for a link wherever its data is used.
			$message .= ' <small><a href="' . esc_url( GeoUpdater::ATTRIBUTION ) . '">' . esc_html__( 'IP Geolocation by DB-IP', 'sentinel-shield' ) . '</a></small>';
		}
		return new \WP_Error( self::ERROR_CODE, $message );
	}
}
