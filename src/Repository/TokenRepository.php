<?php
/**
 * One-time unlock tokens.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Repository;

defined( 'ABSPATH' ) || exit;

/**
 * Only SHA-256 hashes are stored; the plaintext token exists only in the email.
 */
final class TokenRepository {

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
		return $this->db->base_prefix . 'sentinel_unlock_tokens';
	}

	/**
	 * Creates a token and returns its plaintext (64 hex chars).
	 *
	 * @param int    $user_id User ID.
	 * @param string $ip      Requesting IP.
	 * @param int    $ttl     Lifetime in seconds.
	 */
	public function create( int $user_id, string $ip, int $ttl ): string {
		$token = bin2hex( random_bytes( 32 ) );
		$now   = time();
		$this->db->insert(
			$this->table(),
			array(
				'token_hash' => hash( 'sha256', $token ),
				'user_id'    => $user_id,
				'ip_text'    => substr( $ip, 0, 45 ),
				'created_at' => gmdate( 'Y-m-d H:i:s', $now ),
				'expires_at' => gmdate( 'Y-m-d H:i:s', $now + $ttl ),
			),
			array( '%s', '%d', '%s', '%s', '%s' )
		);
		return $token;
	}

	/**
	 * A valid, unused token's row without consuming it (for the confirmation page).
	 *
	 * @param string $token Plaintext token.
	 * @return array<string, mixed>|null
	 */
	public function peek( string $token ): ?array {
		$row = $this->db->get_row(
			$this->db->prepare(
				'SELECT id, user_id, ip_text, created_at, expires_at, used_at FROM %i WHERE token_hash = %s AND used_at IS NULL AND expires_at > %s',
				$this->table(),
				hash( 'sha256', $token ),
				gmdate( 'Y-m-d H:i:s' )
			),
			ARRAY_A
		);
		return is_array( $row ) ? $row : null;
	}

	/**
	 * Atomically marks a valid, unused token as used and returns its row.
	 *
	 * @param string $token Plaintext token.
	 * @return array<string, mixed>|null
	 */
	public function consume( string $token ): ?array {
		$hash = hash( 'sha256', $token );
		$now  = gmdate( 'Y-m-d H:i:s' );
		$done = $this->db->query(
			$this->db->prepare(
				'UPDATE %i SET used_at = %s WHERE token_hash = %s AND used_at IS NULL AND expires_at > %s',
				$this->table(),
				$now,
				$hash,
				$now
			)
		);
		if ( 1 !== (int) $done ) {
			return null;
		}
		$row = $this->db->get_row(
			$this->db->prepare( 'SELECT id, user_id, ip_text, created_at, expires_at, used_at FROM %i WHERE token_hash = %s', $this->table(), $hash ),
			ARRAY_A
		);
		return is_array( $row ) ? $row : null;
	}

	/**
	 * Tokens created since a time, for one account or all.
	 *
	 * @param int      $since   Unix time.
	 * @param int|null $user_id Account, or null for every account.
	 */
	public function count_created( int $since, ?int $user_id = null ): int {
		$since = gmdate( 'Y-m-d H:i:s', $since );
		$sql   = null === $user_id
			? $this->db->prepare( 'SELECT COUNT(*) FROM %i WHERE created_at >= %s', $this->table(), $since )
			: $this->db->prepare( 'SELECT COUNT(*) FROM %i WHERE created_at >= %s AND user_id = %d', $this->table(), $since, $user_id );
		return (int) $this->db->get_var( $sql );
	}

	/**
	 * When the account's newest token was created (Unix time), or 0.
	 *
	 * @param int $user_id Account.
	 */
	public function last_created( int $user_id ): int {
		$at = $this->db->get_var( $this->db->prepare( 'SELECT MAX(created_at) FROM %i WHERE user_id = %d', $this->table(), $user_id ) );
		return is_string( $at ) && '' !== $at ? (int) strtotime( $at . ' UTC' ) : 0;
	}

	/**
	 * Unused, unexpired tokens of an account.
	 *
	 * @param int $user_id Account.
	 */
	public function count_outstanding( int $user_id ): int {
		return (int) $this->db->get_var(
			$this->db->prepare( 'SELECT COUNT(*) FROM %i WHERE user_id = %d AND used_at IS NULL AND expires_at > %s', $this->table(), $user_id, gmdate( 'Y-m-d H:i:s' ) )
		);
	}

	/**
	 * Invalidates every unused token of an account.
	 *
	 * @param int $user_id Account.
	 * @return int Tokens invalidated.
	 */
	public function revoke_user( int $user_id ): int {
		return (int) $this->db->query(
			$this->db->prepare( 'UPDATE %i SET expires_at = %s WHERE user_id = %d AND used_at IS NULL AND expires_at > %s', $this->table(), gmdate( 'Y-m-d H:i:s', time() - 1 ), $user_id, gmdate( 'Y-m-d H:i:s' ) )
		);
	}

	/**
	 * Deletes expired or used tokens older than a day.
	 *
	 * @return int Rows deleted.
	 */
	public function prune(): int {
		return (int) $this->db->query(
			$this->db->prepare( 'DELETE FROM %i WHERE expires_at < %s', $this->table(), gmdate( 'Y-m-d H:i:s', time() - DAY_IN_SECONDS ) )
		);
	}
}
