<?php
/**
 * Short-lived cache for admin report queries.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Support;

defined( 'ABSPATH' ) || exit;

/**
 * Report numbers (counts, top lists) cost grouping queries over tables that
 * grow during attacks. Admin screens can show them a minute old; clearing data
 * bumps a generation number so every cached report is recomputed at once.
 * Enforcement never reads from here.
 */
final class Cached {

	private const GENERATION = 'sentinel_shield_report_gen';

	/**
	 * Returns a cached value or computes and stores it.
	 *
	 * @template T
	 * @param string       $key Key.
	 * @param int          $ttl Seconds.
	 * @param callable():T $compute Computes the value.
	 * @return T
	 */
	public static function remember( string $key, int $ttl, callable $compute ): mixed {
		$name = 'sentinel_shield_r_' . md5( $key . '|' . (int) get_site_option( self::GENERATION, 0 ) );
		$hit  = get_site_transient( $name );
		if ( is_array( $hit ) && array_key_exists( 'v', $hit ) ) {
			return $hit['v'];
		}
		$value = $compute();
		set_site_transient( $name, array( 'v' => $value ), $ttl );
		return $value;
	}

	/**
	 * Invalidates every cached report.
	 */
	public static function bump(): void {
		update_site_option( self::GENERATION, (int) get_site_option( self::GENERATION, 0 ) + 1 );
	}
}
