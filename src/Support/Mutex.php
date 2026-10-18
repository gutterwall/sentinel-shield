<?php
/**
 * Database named locks for read-check-write sequences.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Support;

defined( 'ABSPATH' ) || exit;

/**
 * MySQL/MariaDB GET_LOCK(): one holder per name across all PHP workers, released
 * on RELEASE_LOCK() or when the connection closes (so a crashed request cannot
 * leave a lock behind). Re-entrant within a request.
 *
 * A database that does not support named locks (GET_LOCK() returns NULL, e.g. a
 * SQLite drop-in) does not stop the site: the work runs unlocked, as it would
 * without this class. Only a real timeout (another worker holds the lock) fails.
 */
final class Mutex {

	/**
	 * Hold counts of the locks this request holds.
	 *
	 * @var array<string, int>
	 */
	private static array $held = array();

	/**
	 * Takes a lock, waiting up to $timeout seconds.
	 *
	 * @param string $name    Lock name (any length).
	 * @param int    $timeout Seconds to wait.
	 * @return bool False only when another request holds the lock.
	 */
	public static function acquire( string $name, int $timeout = 5 ): bool {
		if ( isset( self::$held[ $name ] ) ) {
			++self::$held[ $name ];
			return true;
		}
		global $wpdb;
		$sql = $wpdb->prepare( 'SELECT GET_LOCK(%s, %d)', self::db_name( $name ), max( 0, $timeout ) );
		$got = $wpdb->get_var( $sql ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.NotPrepared -- Named locks are not cacheable; prepared above.
		if ( '0' === $got ) {
			return false;
		}
		if ( '1' === (string) $got ) {
			self::$held[ $name ] = 1;
		}
		return true;
	}

	/**
	 * Releases a lock taken with acquire().
	 *
	 * @param string $name Lock name.
	 */
	public static function release( string $name ): void {
		if ( ! isset( self::$held[ $name ] ) ) {
			return;
		}
		if ( --self::$held[ $name ] > 0 ) {
			return;
		}
		unset( self::$held[ $name ] );
		global $wpdb;
		$wpdb->query( $wpdb->prepare( 'SELECT RELEASE_LOCK(%s)', self::db_name( $name ) ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Named locks are not cacheable.
	}

	/**
	 * Runs $work while holding a lock.
	 *
	 * @template T
	 * @param string       $name    Lock name.
	 * @param int          $timeout Seconds to wait.
	 * @param callable():T $work    Work.
	 * @param mixed        $busy    Returned when the lock could not be taken.
	 * @return T|mixed
	 */
	public static function run( string $name, int $timeout, callable $work, mixed $busy = null ): mixed {
		if ( ! self::acquire( $name, $timeout ) ) {
			return $busy;
		}
		try {
			return $work();
		} finally {
			self::release( $name );
		}
	}

	/**
	 * Whether this request holds a lock.
	 *
	 * @param string $name Lock name.
	 */
	public static function holds( string $name ): bool {
		return isset( self::$held[ $name ] );
	}

	/**
	 * Server-wide lock name (64 characters at most), unique per WordPress install.
	 *
	 * @param string $name Lock name.
	 */
	private static function db_name( string $name ): string {
		global $wpdb;
		return 'sentinel_shield_' . md5( DB_NAME . '|' . $wpdb->base_prefix . '|' . $name );
	}
}
