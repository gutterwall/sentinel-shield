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
 *    from mod_geoip or MaxMind's module), current request only. Names starting
 *    with HTTP_ are request headers that any visitor can send, so they are only
 *    used when the request came through a trusted proxy that named the visitor
 *    (the proxy is expected to set or overwrite the header).
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
			$var = $this->server_variable( $ip );
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
	 *
	 * @param string $ip Client IP being resolved ('' = the current request's).
	 */
	public function server_variable( string $ip = '' ): string {
		$name = (string) $this->settings->get( 'geo.server_var', '' );
		if ( '' === $name || ( self::is_header( $name ) && ! $this->header_trusted( $ip ) ) ) {
			return '';
		}
		$code = strtoupper( trim( (string) ( $this->server[ $name ] ?? '' ) ) );
		return CountryList::exists( $code ) ? $code : '';
	}

	/**
	 * Whether a server variable name is really a request header.
	 *
	 * @param string $name Variable name.
	 */
	public static function is_header( string $name ): bool {
		return str_starts_with( strtoupper( $name ), 'HTTP_' );
	}

	/**
	 * Whether request headers on this request were set by a trusted proxy: the
	 * direct peer is trusted and it named the visitor (not a fallback).
	 *
	 * @param string $ip Client IP being resolved ('' = the current request's).
	 */
	public function header_trusted( string $ip = '' ): bool {
		$details = ( $this->details )();
		if ( empty( $details['remote_trusted'] ) || ! empty( $details['fallback'] ) || 'none' === ( $details['mode'] ?? 'none' ) ) {
			return false;
		}
		return '' === $ip || ( $details['ip'] ?? '' ) === $ip;
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
