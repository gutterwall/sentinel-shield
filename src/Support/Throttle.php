<?php
/**
 * Cheap "only once per window" guard for log de-duplication.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Support;

defined( 'ABSPATH' ) || exit;

/**
 * Uses a persistent object cache when available (atomic wp_cache_add); without
 * one, de-duplicates within the current request only, avoiding a DB write per check.
 */
final class Throttle {

	/**
	 * Keys seen in this request.
	 *
	 * @var array<string, true>
	 */
	private static array $seen = array();

	/**
	 * Returns true the first time a key is seen within the TTL.
	 *
	 * @param string $key Key.
	 * @param int    $ttl Seconds.
	 */
	public static function once( string $key, int $ttl ): bool {
		if ( isset( self::$seen[ $key ] ) ) {
			return false;
		}
		self::$seen[ $key ] = true;
		if ( function_exists( 'wp_using_ext_object_cache' ) && wp_using_ext_object_cache() ) {
			return (bool) wp_cache_add( $key, 1, 'sentinel_shield', $ttl );
		}
		return true;
	}
}
