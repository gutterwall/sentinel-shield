<?php
/**
 * Failed login attempts, for the brute-force limits.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Repository;

use SentinelShield\Support\Batch;

defined( 'ABSPATH' ) || exit;

/**
 * One row per failed login (wrong password, unknown user or wrong two-factor
 * code), keyed by binary IP and by account. The account key is "u:<ID>" for an
 * existing account, so its login name and email address count together, or
 * "n:<name>" for a name that matches no account.
 */
final class LoginAttemptRepository {

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
		return $this->db->base_prefix . 'sentinel_login_attempts';
	}

	/**
	 * Counters table: failures per IP and per account in one-minute buckets.
	 * Enforcement reads these; the attempts table is history for reports.
	 */
	public function counters_table(): string {
		return $this->db->base_prefix . 'sentinel_login_counters';
	}

	/**
	 * Records a failed login: one history row, and one atomic increment each of
	 * the IP's and the account's counters.
	 *
	 * @param string $bin     Packed IP.
	 * @param string $account Account key.
	 * @param int    $time    Unix time.
	 */
	public function record( string $bin, string $account, int $time ): void {
		$account = mb_substr( $account, 0, 64 );
		$this->db->query(
			$this->db->prepare(
				'INSERT INTO %i (ip, account, created_at) VALUES (UNHEX(%s), %s, %s)',
				$this->table(),
				bin2hex( $bin ),
				$account,
				gmdate( 'Y-m-d H:i:s', $time )
			)
		);
		$bucket = intdiv( $time, 60 );
		$this->db->query(
			$this->db->prepare(
				'INSERT INTO %i (scope, subject, bucket, n) VALUES (%s, %s, %d, 1), (%s, %s, %d, 1) ON DUPLICATE KEY UPDATE n = n + 1',
				$this->counters_table(),
				'i',
				bin2hex( $bin ),
				$bucket,
				'a',
				$account,
				$bucket
			)
		);
	}

	/**
	 * Failures counted against an IP since a time.
	 *
	 * @param string $bin   Packed IP.
	 * @param int    $since Unix time.
	 */
	public function count_ip( string $bin, int $since ): int {
		return $this->counter( 'i', bin2hex( $bin ), $since );
	}

	/**
	 * Failures counted against an account since a time; with $ips, also the
	 * number of distinct IPs in the history (a heavier query, for reports).
	 *
	 * @param string $account Account key.
	 * @param int    $since   Unix time.
	 * @param bool   $ips     Also count distinct IPs.
	 * @return array{failures:int, ips:int}
	 */
	public function count_account( string $account, int $since, bool $ips = false ): array {
		$distinct = 0;
		if ( $ips ) {
			$distinct = (int) $this->db->get_var(
				$this->db->prepare( 'SELECT COUNT(DISTINCT ip) FROM %i WHERE account = %s AND created_at >= %s', $this->table(), $account, gmdate( 'Y-m-d H:i:s', $since ) )
			);
		}
		return array(
			'failures' => $this->counter( 'a', mb_substr( $account, 0, 64 ), $since ),
			'ips'      => $distinct,
		);
	}

	/**
	 * Sum of one counter's buckets since a time.
	 *
	 * @param string $scope   i or a.
	 * @param string $subject Hex IP or account key.
	 * @param int    $since   Unix time.
	 */
	private function counter( string $scope, string $subject, int $since ): int {
		return (int) $this->db->get_var(
			$this->db->prepare( 'SELECT COALESCE(SUM(n), 0) FROM %i WHERE scope = %s AND subject = %s AND bucket >= %d', $this->counters_table(), $scope, $subject, intdiv( $since, 60 ) )
		);
	}

	/**
	 * Resets only an IP's enforcement counter (after it was locked out, so the
	 * next lockout needs a fresh run). The history and the account counters it
	 * contributed to are kept: they still count toward distributed-attack limits.
	 *
	 * @param string $bin Packed IP.
	 */
	public function reset_ip_counter( string $bin ): void {
		$this->db->query( $this->db->prepare( 'DELETE FROM %i WHERE scope = %s AND subject = %s', $this->counters_table(), 'i', bin2hex( $bin ) ) );
	}

	/**
	 * Forgets an IP's failures.
	 *
	 * @param string $bin Packed IP.
	 */
	public function clear_ip( string $bin ): int {
		$this->reset_ip_counter( $bin );
		return (int) $this->db->query( $this->db->prepare( 'DELETE FROM %i WHERE ip = UNHEX(%s)', $this->table(), bin2hex( $bin ) ) );
	}

	/**
	 * Forgets an account's failures.
	 *
	 * @param string $account Account key.
	 */
	public function clear_account( string $account ): int {
		$this->db->query( $this->db->prepare( 'DELETE FROM %i WHERE scope = %s AND subject = %s', $this->counters_table(), 'a', mb_substr( $account, 0, 64 ) ) );
		return (int) $this->db->query( $this->db->prepare( 'DELETE FROM %i WHERE account = %s', $this->table(), $account ) );
	}

	/**
	 * Forgets every failure.
	 */
	public function clear_all(): int {
		$this->db->query( $this->db->prepare( 'DELETE FROM %i', $this->counters_table() ) );
		return (int) $this->db->query( $this->db->prepare( 'DELETE FROM %i', $this->table() ) );
	}

	/**
	 * IPs with the most failures since a time.
	 *
	 * @param int $since Unix time.
	 * @param int $limit Rows.
	 * @return list<array{ip:string, failures:int, accounts:int, last:string}>
	 */
	public function top_ips( int $since, int $limit = 10 ): array {
		$rows = (array) $this->db->get_results(
			$this->db->prepare(
				'SELECT ip, COUNT(*) AS failures, COUNT(DISTINCT account) AS accounts, MAX(created_at) AS last FROM %i WHERE created_at >= %s GROUP BY ip ORDER BY failures DESC LIMIT %d',
				$this->table(),
				gmdate( 'Y-m-d H:i:s', $since ),
				$limit
			),
			ARRAY_A
		);
		return array_map(
			static fn( array $r ): array => array(
				'ip'       => (string) inet_ntop( (string) $r['ip'] ),
				'failures' => (int) $r['failures'],
				'accounts' => (int) $r['accounts'],
				'last'     => (string) $r['last'],
			),
			$rows
		);
	}

	/**
	 * Accounts with the most failures since a time.
	 *
	 * @param int $since Unix time.
	 * @param int $limit Rows.
	 * @return list<array{account:string, failures:int, ips:int, last:string}>
	 */
	public function top_accounts( int $since, int $limit = 10 ): array {
		$rows = (array) $this->db->get_results(
			$this->db->prepare(
				'SELECT account, COUNT(*) AS failures, COUNT(DISTINCT ip) AS ips, MAX(created_at) AS last FROM %i WHERE created_at >= %s GROUP BY account ORDER BY failures DESC LIMIT %d',
				$this->table(),
				gmdate( 'Y-m-d H:i:s', $since ),
				$limit
			),
			ARRAY_A
		);
		return array_map(
			static fn( array $r ): array => array(
				'account'  => (string) $r['account'],
				'failures' => (int) $r['failures'],
				'ips'      => (int) $r['ips'],
				'last'     => (string) $r['last'],
			),
			$rows
		);
	}

	/**
	 * Total failures since a time.
	 *
	 * @param int $since Unix time.
	 */
	public function count_since( int $since ): int {
		return (int) $this->db->get_var( $this->db->prepare( 'SELECT COUNT(*) FROM %i WHERE created_at >= %s', $this->table(), gmdate( 'Y-m-d H:i:s', $since ) ) );
	}

	/**
	 * Deletes failures older than a time.
	 *
	 * @param int $before Unix time.
	 * @return int Rows deleted.
	 */
	public function prune( int $before ): int {
		$this->db->query( $this->db->prepare( 'DELETE FROM %i WHERE bucket < %d', $this->counters_table(), intdiv( $before, 60 ) ) );
		return Batch::delete( $this->db, $this->db->prepare( 'DELETE FROM %i WHERE created_at < %s', $this->table(), gmdate( 'Y-m-d H:i:s', $before ) ) );
	}
}
