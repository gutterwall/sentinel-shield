<?php
/**
 * Works out which country an IP address is in.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Geo;

use SentinelShield\Net\IpAddress;
use SentinelShield\Settings;

defined( 'ABSPATH' ) || exit;

/**
 * Sources, in order:
 * 1. Cloudflare's CF-IPCountry header, only for the current request, only with
 *    the Cloudflare proxy preset, and only when the request really came through
 *    Cloudflare (otherwise anyone could send the header).
 * 2. A server variable set by the web server or hosting (e.g. GEOIP_COUNTRY_CODE
 *    from mod_geoip or MaxMind's module), current request only.
 * 3. The local DB-IP database, for any address.
 * Private and reserved addresses have no country.
 */
final class GeoResolver {

	/**
	 * Constructor.
	 *
	 * @param Settings             $settings Settings.
	 * @param CountryDatabase      $db       Local database.
	 * @param array<string, mixed> $server   $_SERVER.
	 * @param \Closure             $details  Returns the current request's client IP details.
	 */
	public function __construct( private Settings $settings, private CountryDatabase $db, private array $server, private \Closure $details ) {}

	/**
	 * Country for an IP.
	 *
	 * @param string $ip      IP address.
	 * @param bool   $current Whether $ip is the current request's client IP (enables header sources).
	 * @return array{country:string, source:string} Source: cloudflare, server, dbip, private, invalid or none.
	 */
	public function resolve( string $ip, bool $current = false ): array {
		$bin = IpAddress::to_binary( $ip );
		if ( null === $bin ) {
			return self::result( '', 'invalid' );
		}
		if ( IpAddress::is_private( $bin ) ) {
			return self::result( '', 'private' );
		}
		if ( $current ) {
			$cf = $this->cloudflare( $ip );
			if ( '' !== $cf ) {
				return self::result( $cf, 'cloudflare' );
			}
			$var = $this->server_variable();
			if ( '' !== $var ) {
				return self::result( $var, 'server' );
			}
		}
		$code = $this->db->lookup( $bin );
		return '' !== $code && CountryList::exists( $code ) ? self::result( $code, 'dbip' ) : self::result( '', 'none' );
	}

	/**
	 * Cloudflare's country for the current request, or ''.
	 *
	 * @param string $ip Client IP being resolved.
	 */
	public function cloudflare( string $ip = '' ): string {
		$details = ( $this->details )();
		if ( 'cloudflare' !== ( $details['mode'] ?? '' ) || empty( $details['remote_trusted'] ) || ! empty( $details['fallback'] ) ) {
			return '';
		}
		if ( '' !== $ip && ( $details['ip'] ?? '' ) !== $ip ) {
			return '';
		}
		$code = strtoupper( trim( (string) ( $this->server['HTTP_CF_IPCOUNTRY'] ?? '' ) ) );
		return CountryList::exists( $code ) ? $code : '';
	}

	/**
	 * The configured server variable's country, or ''.
	 */
	public function server_variable(): string {
		$name = (string) $this->settings->get( 'geo.server_var', '' );
		if ( '' === $name ) {
			return '';
		}
		$code = strtoupper( trim( (string) ( $this->server[ $name ] ?? '' ) ) );
		return CountryList::exists( $code ) ? $code : '';
	}

	/**
	 * The local database.
	 */
	public function database(): CountryDatabase {
		return $this->db;
	}

	/**
	 * Result shape.
	 *
	 * @param string $country Code or ''.
	 * @param string $source  Source.
	 * @return array{country:string, source:string}
	 */
	private static function result( string $country, string $source ): array {
		return array(
			'country' => $country,
			'source'  => $source,
		);
	}
}
