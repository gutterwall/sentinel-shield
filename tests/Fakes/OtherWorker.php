<?php
/**
 * Another PHP worker, as far as locks are concerned.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Tests\Fakes;

use SentinelShield\Support\Mutex;

/**
 * Holds Mutex locks on a database connection of its own, like a second PHP
 * worker would, and can take a lock away from this process the way a lost
 * database connection does (MySQL releases named locks with the connection,
 * and another worker gets them).
 */
final class OtherWorker {

	private \wpdb $db;

	/**
	 * Locks taken.
	 *
	 * @var array<string, bool>
	 */
	private array $held = array();

	public function __construct() {
		$this->db = new \wpdb( DB_USER, DB_PASSWORD, DB_NAME, DB_HOST );
		$this->db->suppress_errors( true );
	}

	/**
	 * The database lock name Mutex uses for a name.
	 *
	 * @param string $name Lock name.
	 */
	public static function lock_name( string $name ): string {
		$method = new \ReflectionMethod( Mutex::class, 'db_name' );
		return (string) $method->invoke( null, $name );
	}

	/**
	 * Takes a lock nobody holds.
	 *
	 * @param string $name Lock name.
	 */
	public function hold( string $name ): bool {
		$got = '1' === (string) $this->db->get_var( $this->db->prepare( 'SELECT GET_LOCK(%s, 0)', self::lock_name( $name ) ) );
		if ( $got ) {
			$this->held[ $name ] = true;
		}
		return $got;
	}

	/**
	 * This process's connection loses the lock (as when it is re-established)
	 * and this worker takes it.
	 *
	 * @param string $name Lock name.
	 */
	public function steal( string $name ): bool {
		global $wpdb;
		$wpdb->query( $wpdb->prepare( 'SELECT RELEASE_LOCK(%s)', self::lock_name( $name ) ) );
		return $this->hold( $name );
	}

	/**
	 * Whether this worker holds a lock.
	 *
	 * @param string $name Lock name.
	 */
	public function holds( string $name ): bool {
		return '1' === (string) $this->db->get_var( $this->db->prepare( 'SELECT IS_USED_LOCK(%s) = CONNECTION_ID()', self::lock_name( $name ) ) );
	}

	/**
	 * Releases a lock.
	 *
	 * @param string $name Lock name.
	 */
	public function release( string $name ): void {
		$this->db->query( $this->db->prepare( 'SELECT RELEASE_LOCK(%s)', self::lock_name( $name ) ) );
		unset( $this->held[ $name ] );
	}

	/**
	 * Releases every lock this worker took (at once: a closed connection's
	 * locks are freed only when the server gets round to it) and ends the
	 * connection.
	 */
	public function close(): void {
		foreach ( array_keys( $this->held ) as $name ) {
			$this->release( $name );
		}
		$this->db->close();
	}
}
