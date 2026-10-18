<?php
/**
 * Offense history used for progressive lockouts.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Repository;

use SentinelShield\Lockout\OffenseStore;

use SentinelShield\Support\Batch;

defined( 'ABSPATH' ) || exit;

/**
 * One row per lockout, keyed by binary IP.
 */
final class OffenseRepository implements OffenseStore {

	/**
	 * Constructor.
	 *
	 * @param \wpdb $db Database.
	 */
	public function __construct( private \wpdb $db ) {}

	/**
	 * Table name.
	 */
	public function table(): string {
		return $this->db->base_prefix . 'sentinel_offenses';
	}

	/**
	 * {@inheritDoc}
	 *
	 * @param string $bin     Packed IP.
	 * @param int    $since   Unix time.
	 * @param bool   $is_test Count test-mode offenses instead of real ones.
	 */
	public function count_recent( string $bin, int $since, bool $is_test ): int {
		return (int) $this->db->get_var(
			$this->db->prepare(
				'SELECT COUNT(*) FROM %i WHERE ip = UNHEX(%s) AND is_test = %d AND created_at >= %s',
				$this->table(),
				bin2hex( $bin ),
				$is_test ? 1 : 0,
				gmdate( 'Y-m-d H:i:s', $since )
			)
		);
	}

	/**
	 * {@inheritDoc}
	 *
	 * @param string $bin     Packed IP.
	 * @param string $module  Module slug.
	 * @param string $reason  Reason.
	 * @param bool   $is_test Test mode offense.
	 * @param int    $time    Unix time.
	 */
	public function record( string $bin, string $module, string $reason, bool $is_test, int $time ): void {
		$this->db->query(
			$this->db->prepare(
				'INSERT INTO %i (ip, module, reason, is_test, created_at) VALUES (UNHEX(%s), %s, %s, %d, %s)',
				$this->table(),
				bin2hex( $bin ),
				substr( sanitize_key( $module ), 0, 32 ),
				mb_substr( $reason, 0, 255 ),
				$is_test ? 1 : 0,
				gmdate( 'Y-m-d H:i:s', $time )
			)
		);
	}

	/**
	 * {@inheritDoc}
	 *
	 * @param string $bin Packed IP.
	 */
	public function clear( string $bin ): void {
		$this->db->query( $this->db->prepare( 'DELETE FROM %i WHERE ip = UNHEX(%s)', $this->table(), bin2hex( $bin ) ) );
	}

	/**
	 * Deletes offenses older than a timestamp.
	 *
	 * @param int $before Unix time.
	 * @return int Rows deleted.
	 */
	public function prune( int $before ): int {
		return Batch::delete( $this->db, $this->db->prepare( 'DELETE FROM %i WHERE created_at < %s', $this->table(), gmdate( 'Y-m-d H:i:s', $before ) ) );
	}
}
