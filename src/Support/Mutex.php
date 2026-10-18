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
 * When GET_LOCK() gives no answer (a database error, a database proxy that does
 * not pass named locks through, or a backend without them such as a SQLite
 * drop-in), an atomic lock row in the options table is used instead: INSERT
 * IGNORE succeeds for exactly one worker, and a row older than its lease can be
 * taken over with a compare-and-set. If that fails too, the lock is reported as
 * not acquired, so callers refuse the sensitive operation rather than run it
 * unprotected. The mode in use is recorded for the health screen.
 */
final class Mutex {

	public const HEALTH_OPTION = 'sentinel_shield_lock_health';

	private const LEASE = 60;

	/**
	 * Hold counts of the locks this request holds.
	 *
	 * @var array<string, int>
	 */
	private static array $held = array();

	/**
	 * How each held lock was taken: native or row.
	 *
	 * @var array<string, string>
	 */
	private static array $how = array();

	/**
	 * Value of each lock row this request holds ("<lease end>|<owner token>").
	 *
	 * @var array<string, string>
	 */
	private static array $rows = array();

	/**
	 * Takes a lock, waiting up to $timeout seconds.
	 *
	 * @param string $name    Lock name (any length).
	 * @param int    $timeout Seconds to wait.
	 * @return bool False when another request holds the lock, or no lock can be taken at all.
	 */
	public static function acquire( string $name, int $timeout = 5 ): bool {
		if ( isset( self::$held[ $name ] ) ) {
			++self::$held[ $name ];
			return true;
		}
		global $wpdb;
		$sql      = $wpdb->prepare( 'SELECT GET_LOCK(%s, %d)', self::db_name( $name ), max( 0, $timeout ) );
		$suppress = $wpdb->suppress_errors( true );
		$got      = $wpdb->get_var( $sql ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.NotPrepared -- Named locks are not cacheable; prepared above.
		$wpdb->suppress_errors( $suppress );
		if ( '0' === $got ) {
			return false;
		}
		if ( '1' === (string) $got ) {
			self::$held[ $name ] = 1;
			self::$how[ $name ]  = 'native';
			self::health( 'native' );
			return true;
		}
		return self::acquire_row( $name, $timeout );
	}

	/**
	 * Fallback: a lock row in the options table.
	 *
	 * @param string $name    Lock name.
	 * @param int    $timeout Seconds to wait.
	 */
	private static function acquire_row( string $name, int $timeout ): bool {
		global $wpdb;
		$table    = $wpdb->base_prefix . 'options';
		$key      = '_' . self::db_name( $name );
		$deadline = microtime( true ) + max( 0, $timeout );
		$suppress = $wpdb->suppress_errors( true );
		try {
			do {
				$now   = time();
				$value = ( $now + self::LEASE ) . '|' . bin2hex( random_bytes( 8 ) );
				$ins   = $wpdb->query( $wpdb->prepare( 'INSERT IGNORE INTO %i (option_name, option_value, autoload) VALUES (%s, %s, %s)', $table, $key, $value, 'no' ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- A lock row must bypass the options cache.
				if ( false === $ins ) {
					self::health( 'failed', (string) $wpdb->last_error );
					return false;
				}
				if ( 1 === (int) $ins ) {
					return self::took_row( $name, $value );
				}
				// Held by someone; take it over only once its lease has run out.
				$until = $wpdb->get_var( $wpdb->prepare( 'SELECT option_value FROM %i WHERE option_name = %s', $table, $key ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- See above.
				if ( null !== $until && (int) $until < $now ) {
					$cas = $wpdb->query( $wpdb->prepare( 'UPDATE %i SET option_value = %s WHERE option_name = %s AND option_value = %s', $table, $value, $key, (string) $until ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- See above.
					if ( 1 === (int) $cas ) {
						return self::took_row( $name, $value );
					}
				}
				if ( microtime( true ) >= $deadline ) {
					return false;
				}
				usleep( 100000 );
			} while ( true );
		} finally {
			$wpdb->suppress_errors( $suppress );
		}
	}

	/**
	 * Notes a lock taken with a lock row.
	 *
	 * @param string $name  Lock name.
	 * @param string $value Row value (lease end and owner token).
	 */
	private static function took_row( string $name, string $value ): bool {
		self::$held[ $name ] = 1;
		self::$how[ $name ]  = 'row';
		self::$rows[ $name ] = $value;
		self::health( 'row' );
		return true;
	}

	/**
	 * Records which locking mode works on this site (only when it changes).
	 *
	 * @param string $mode  native, row or failed.
	 * @param string $error Database error, if any.
	 */
	private static function health( string $mode, string $error = '' ): void {
		static $noted = array();
		if ( isset( $noted[ $mode ] ) || ! function_exists( 'get_site_option' ) ) {
			return;
		}
		$noted[ $mode ] = true;
		$stored         = get_site_option( self::HEALTH_OPTION );
		if ( is_array( $stored ) && ( $stored['mode'] ?? '' ) === $mode && 'failed' !== $mode ) {
			return;
		}
		update_site_option(
			self::HEALTH_OPTION,
			array(
				'mode'  => $mode,
				'time'  => time(),
				'error' => mb_substr( $error, 0, 200 ),
			)
		);
	}

	/**
	 * Last recorded locking mode: {mode: native|row|failed, time, error}, or null.
	 *
	 * @return array{mode:string, time:int, error:string}|null
	 */
	public static function status(): ?array {
		$stored = get_site_option( self::HEALTH_OPTION );
		return is_array( $stored ) ? $stored : null;
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
		if ( 'row' === ( self::$how[ $name ] ?? '' ) ) {
			// Only our own row: if our lease ran out and another worker took over, its lock stays.
			$wpdb->query( $wpdb->prepare( 'DELETE FROM %i WHERE option_name = %s AND option_value = %s', $wpdb->base_prefix . 'options', '_' . self::db_name( $name ), (string) ( self::$rows[ $name ] ?? '' ) ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Lock row.
			unset( self::$rows[ $name ] );
		} else {
			$wpdb->query( $wpdb->prepare( 'SELECT RELEASE_LOCK(%s)', self::db_name( $name ) ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Named locks are not cacheable.
		}
		unset( self::$how[ $name ] );
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
	 * Extends a held lock row's lease (call during long work). Named locks need
	 * no renewal. Returns false when the lease was lost to another worker.
	 *
	 * @param string $name Lock name.
	 */
	public static function renew( string $name ): bool {
		if ( 'row' !== ( self::$how[ $name ] ?? '' ) ) {
			return isset( self::$held[ $name ] );
		}
		global $wpdb;
		$value = ( time() + self::LEASE ) . '|' . substr( (string) self::$rows[ $name ], (int) strpos( (string) self::$rows[ $name ], '|' ) + 1 );
		if ( $value === self::$rows[ $name ] ) {
			// Same second: nothing to extend (MySQL would report 0 rows changed); just check we still own it.
			return self::$rows[ $name ] === $wpdb->get_var( $wpdb->prepare( 'SELECT option_value FROM %i WHERE option_name = %s', $wpdb->base_prefix . 'options', '_' . self::db_name( $name ) ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Lock row.
		}
		$done = $wpdb->query( $wpdb->prepare( 'UPDATE %i SET option_value = %s WHERE option_name = %s AND option_value = %s', $wpdb->base_prefix . 'options', $value, '_' . self::db_name( $name ), (string) self::$rows[ $name ] ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Lock row.
		if ( 1 !== (int) $done ) {
			return false;
		}
		self::$rows[ $name ] = $value;
		return true;
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
