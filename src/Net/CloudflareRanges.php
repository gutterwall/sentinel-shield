<?php
/**
 * Cloudflare edge IP ranges with weekly auto-update.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Net;

defined( 'ABSPATH' ) || exit;

/**
 * Provides Cloudflare ranges: the last successful download, or a bundled copy.
 */
final class CloudflareRanges {

	public const OPTION = 'sentinel_shield_cloudflare_ranges';
	public const URL    = 'https://api.cloudflare.com/client/v4/ips';

	/**
	 * Snapshot shipped with the plugin, used until the first refresh succeeds.
	 */
	public const BUNDLED = array(
		'173.245.48.0/20',
		'103.21.244.0/22',
		'103.22.200.0/22',
		'103.31.4.0/22',
		'141.101.64.0/18',
		'108.162.192.0/18',
		'190.93.240.0/20',
		'188.114.96.0/20',
		'197.234.240.0/22',
		'198.41.128.0/17',
		'162.158.0.0/15',
		'104.16.0.0/13',
		'104.24.0.0/14',
		'172.64.0.0/13',
		'131.0.72.0/22',
		'2400:cb00::/32',
		'2606:4700::/32',
		'2803:f800::/32',
		'2405:b500::/32',
		'2405:8100::/32',
		'2a06:98c0::/29',
		'2c0f:f248::/32',
	);

	/**
	 * Current ranges.
	 *
	 * @return list<string>
	 */
	public function all(): array {
		$stored = get_site_option( self::OPTION );
		if ( is_array( $stored ) && ! empty( $stored['ranges'] ) && is_array( $stored['ranges'] ) ) {
			return array_values( array_map( 'strval', $stored['ranges'] ) );
		}
		return self::BUNDLED;
	}

	/**
	 * Unix time of the last successful refresh, 0 when using the bundled list.
	 */
	public function last_updated(): int {
		$stored = get_site_option( self::OPTION );
		return is_array( $stored ) ? (int) ( $stored['updated'] ?? 0 ) : 0;
	}

	/**
	 * Downloads the list from Cloudflare's public API (no account needed). Keeps
	 * the previous list unless the new one looks sane.
	 *
	 * @return bool|\WP_Error
	 */
	public function refresh(): bool|\WP_Error {
		$response = wp_safe_remote_get(
			self::URL,
			array(
				'timeout'     => 10,
				'redirection' => 2,
			)
		);
		if ( is_wp_error( $response ) ) {
			return $response;
		}
		$data = json_decode( (string) wp_remote_retrieve_body( $response ), true );
		if ( 200 !== (int) wp_remote_retrieve_response_code( $response ) || ! is_array( $data ) || empty( $data['success'] ) || ! isset( $data['result'] ) || ! is_array( $data['result'] ) ) {
			/* translators: %s: URL. */
			return new \WP_Error( 'sentinel_shield_cf_http', sprintf( __( 'Unexpected response from %s.', 'sentinel-shield' ), self::URL ) );
		}
		$ranges = array();
		$counts = array(
			'ipv4_cidrs' => 0,
			'ipv6_cidrs' => 0,
		);
		foreach ( array_keys( $counts ) as $key ) {
			foreach ( (array) ( $data['result'][ $key ] ?? array() ) as $range ) {
				$range = trim( (string) $range );
				if ( '' !== $range && null !== Cidr::parse( $range ) ) {
					$ranges[] = $range;
					++$counts[ $key ];
				}
			}
		}
		if ( $counts['ipv4_cidrs'] < 5 || $counts['ipv6_cidrs'] < 2 ) {
			return new \WP_Error( 'sentinel_shield_cf_invalid', __( 'The downloaded Cloudflare list looked incomplete, so the previous list was kept.', 'sentinel-shield' ) );
		}
		update_site_option(
			self::OPTION,
			array(
				'ranges'  => $ranges,
				'updated' => time(),
			)
		);
		return true;
	}
}
