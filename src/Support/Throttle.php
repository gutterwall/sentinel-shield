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
 * Uses a persistent object cache when available (atomic wp_cache_add). Without
 * one it falls back to a transient, so a flood of blocked requests costs one
 * read per request instead of one log row per request. Only callers on paths
 * that already decided to block use it, so legitimate traffic never pays for it.
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
		$transient = 'sentinel_shield_t_' . md5( $key );
		if ( false !== get_transient( $transient ) ) {
			return false;
		}
		set_transient( $transient, 1, $ttl );
		return true;
	}

	/**
	 * Combines once() with a shared fixed-window budget, read-only checks first:
	 * true (and both recorded) only if the key was not seen within $ttl and fewer
	 * than $limit keys passed in the current window. Rejected calls write nothing,
	 * so total writes stay bounded even when every call uses a new key.
	 *
	 * @param string $key       Per-subject key.
	 * @param int    $ttl       Seconds a key stays "seen".
	 * @param string $budget    Shared budget name.
	 * @param int    $limit     Keys allowed per window.
	 * @param int    $window    Window length in seconds.
	 */
	public static function once_within_budget( string $key, int $ttl, string $budget, int $limit, int $window ): bool {
		if ( isset( self::$seen[ $key ] ) ) {
			return false;
		}
		self::$seen[ $key ] = true;
		$group              = 'sentinel_shield';
		$slot               = 'sentinel_shield_b_' . md5( $budget ) . '_' . intdiv( time(), $window );
		if ( function_exists( 'wp_using_ext_object_cache' ) && wp_using_ext_object_cache() ) {
			if ( false !== wp_cache_get( $key, $group ) || (int) wp_cache_get( $slot, $group ) >= $limit ) {
				return false;
			}
			if ( ! wp_cache_add( $key, 1, $group, $ttl ) ) {
				return false;
			}
			wp_cache_add( $slot, 0, $group, $window );
			return (int) wp_cache_incr( $slot, 1, $group ) <= $limit;
		}
		$transient = 'sentinel_shield_t_' . md5( $key );
		$used      = (int) get_transient( $slot );
		if ( false !== get_transient( $transient ) || $used >= $limit ) {
			return false;
		}
		set_transient( $transient, 1, $ttl );
		set_transient( $slot, $used + 1, $window );
		return true;
	}
}
