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
	public const URL_V4 = 'https://www.cloudflare.com/ips-v4';
	public const URL_V6 = 'https://www.cloudflare.com/ips-v6';

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
	 * Downloads both lists. Keeps the previous list unless the new one looks sane.
	 *
	 * @return bool|\WP_Error
	 */
	public function refresh(): bool|\WP_Error {
		$ranges = array();
		$counts = array(
			'v4' => 0,
			'v6' => 0,
		);
		foreach ( array(
			'v4' => self::URL_V4,
			'v6' => self::URL_V6,
		) as $kind => $url ) {
			$response = wp_safe_remote_get(
				$url,
				array(
					'timeout'     => 10,
					'redirection' => 2,
				)
			);
			if ( is_wp_error( $response ) ) {
				return $response;
			}
			if ( 200 !== (int) wp_remote_retrieve_response_code( $response ) ) {
				/* translators: %s: URL. */
				return new \WP_Error( 'sentinel_shield_cf_http', sprintf( __( 'Unexpected response from %s.', 'sentinel-shield' ), $url ) );
			}
			$lines = preg_split( '/\R/', (string) wp_remote_retrieve_body( $response ) );
			foreach ( false === $lines ? array() : $lines as $line ) {
				$line = trim( $line );
				if ( '' !== $line && null !== Cidr::parse( $line ) ) {
					$ranges[] = $line;
					++$counts[ $kind ];
				}
			}
		}
		if ( $counts['v4'] < 5 || $counts['v6'] < 2 ) {
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
