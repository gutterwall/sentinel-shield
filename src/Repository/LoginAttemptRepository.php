<?php
/**
 * Failed login attempts, for the brute-force limits.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Repository;

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
	 * Records a failure.
	 *
	 * @param string $bin     Packed IP.
	 * @param string $account Account key.
	 * @param int    $time    Unix time.
	 */
	public function record( string $bin, string $account, int $time ): void {
		$this->db->query(
			$this->db->prepare(
				'INSERT INTO %i (ip, account, created_at) VALUES (UNHEX(%s), %s, %s)',
				$this->table(),
				bin2hex( $bin ),
				mb_substr( $account, 0, 64 ),
				gmdate( 'Y-m-d H:i:s', $time )
			)
		);
	}

	/**
	 * Failures from an IP since a time.
	 *
	 * @param string $bin   Packed IP.
	 * @param int    $since Unix time.
	 */
	public function count_ip( string $bin, int $since ): int {
		return (int) $this->db->get_var(
			$this->db->prepare( 'SELECT COUNT(*) FROM %i WHERE ip = UNHEX(%s) AND created_at >= %s', $this->table(), bin2hex( $bin ), gmdate( 'Y-m-d H:i:s', $since ) )
		);
	}

	/**
	 * Failures against an account since a time, and from how many IPs.
	 *
	 * @param string $account Account key.
	 * @param int    $since   Unix time.
	 * @return array{failures:int, ips:int}
	 */
	public function count_account( string $account, int $since ): array {
		$row = $this->db->get_row(
			$this->db->prepare( 'SELECT COUNT(*) AS failures, COUNT(DISTINCT ip) AS ips FROM %i WHERE account = %s AND created_at >= %s', $this->table(), $account, gmdate( 'Y-m-d H:i:s', $since ) ),
			ARRAY_A
		);
		return array(
			'failures' => (int) ( $row['failures'] ?? 0 ),
			'ips'      => (int) ( $row['ips'] ?? 0 ),
		);
	}

	/**
	 * Forgets an IP's failures.
	 *
	 * @param string $bin Packed IP.
	 */
	public function clear_ip( string $bin ): int {
		return (int) $this->db->query( $this->db->prepare( 'DELETE FROM %i WHERE ip = UNHEX(%s)', $this->table(), bin2hex( $bin ) ) );
	}

	/**
	 * Forgets an account's failures.
	 *
	 * @param string $account Account key.
	 */
	public function clear_account( string $account ): int {
		return (int) $this->db->query( $this->db->prepare( 'DELETE FROM %i WHERE account = %s', $this->table(), $account ) );
	}

	/**
	 * Forgets every failure.
	 */
	public function clear_all(): int {
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
		return (int) $this->db->query( $this->db->prepare( 'DELETE FROM %i WHERE created_at < %s', $this->table(), gmdate( 'Y-m-d H:i:s', $before ) ) );
	}
}
