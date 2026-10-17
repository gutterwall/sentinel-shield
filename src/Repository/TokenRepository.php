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
