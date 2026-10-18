<?php
/**
 * IP rule (block/allow) persistence.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Repository;

use SentinelShield\Net\Cidr;

defined( 'ABSPATH' ) || exit;

/**
 * Rows store each rule as an inclusive binary range. Binary values are passed as
 * hex and converted with UNHEX()/HEX() so raw bytes never travel over a utf8mb4
 * connection, where MySQL could reject or mangle them.
 */
final class BlockRepository {

	private const COLUMNS = 'id, list_type, ip_version, HEX(ip_start) AS start_hex, HEX(ip_end) AS end_hex, prefix, label, reason, source, created_by, created_at, expires_at, hits, last_hit_at';

	/**
	 * Sources treated as "manual" for test mode scope.
	 */
	public const MANUAL_SOURCES = array( 'manual', 'import', 'cli' );

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
		return $this->db->base_prefix . 'sentinel_ip_rules';
	}

	/**
	 * Adds a rule, or updates an identical one (same list and range) in place.
	 * When merging, a permanent rule stays permanent and the later expiry wins.
	 *
	 * @param string   $type    "block" or "allow".
	 * @param Cidr     $cidr    Range.
	 * @param string   $reason  Reason.
	 * @param string   $source  Source module or "manual".
	 * @param int|null $expires Unix expiry, null = permanent.
	 * @param int      $user_id Creating user.
	 * @return int Rule ID.
	 */
	public function add( string $type, Cidr $cidr, string $reason, string $source, ?int $expires = null, int $user_id = 0 ): int {
		$type     = 'allow' === $type ? 'allow' : 'block';
		$now      = gmdate( 'Y-m-d H:i:s' );
		$exp      = null === $expires ? null : gmdate( 'Y-m-d H:i:s', $expires );
		$reason   = mb_substr( $reason, 0, 255 );
		$source   = substr( sanitize_key( $source ), 0, 32 );
		$existing = $this->find_exact( $type, $cidr );

		if ( null !== $existing ) {
			$old = $existing['expires_at'];
			if ( null === $old || null === $exp ) {
				$new = null;
			} else {
				$new = strcmp( $exp, (string) $old ) > 0 ? $exp : $old;
			}
			$this->db->update(
				$this->table(),
				array(
					'reason'     => $reason,
					'source'     => $source,
					'expires_at' => $new,
				),
				array( 'id' => (int) $existing['id'] )
			);
			return (int) $existing['id'];
		}

		$this->db->query(
			$this->db->prepare(
				"INSERT INTO %i (list_type, ip_version, ip_start, ip_end, prefix, label, reason, source, created_by, created_at, expires_at)
				VALUES (%s, %d, UNHEX(%s), UNHEX(%s), %d, %s, %s, %s, %d, %s, NULLIF(%s, ''))",
				$this->table(),
				$type,
				$cidr->version,
				bin2hex( $cidr->start ),
				bin2hex( $cidr->end ),
				$cidr->prefix,
				$cidr->to_string(),
				$reason,
				$source,
				$user_id,
				$now,
				(string) $exp
			)
		);
		return (int) $this->db->insert_id;
	}

	/**
	 * One rule by ID.
	 *
	 * @param int $id Rule ID.
	 * @return array<string, mixed>|null
	 */
	public function get( int $id ): ?array {
		$row = $this->db->get_row(
			$this->db->prepare( 'SELECT ' . self::COLUMNS . ' FROM %i WHERE id = %d', $this->table(), $id ), // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- COLUMNS is a constant.
			ARRAY_A
		);
		return is_array( $row ) ? $row : null;
	}

	/**
	 * Rule with exactly this list and range.
	 *
	 * @param string $type List type.
	 * @param Cidr   $cidr Range.
	 * @return array<string, mixed>|null
	 */
	public function find_exact( string $type, Cidr $cidr ): ?array {
		$row = $this->db->get_row(
			$this->db->prepare(
				'SELECT ' . self::COLUMNS . ' FROM %i WHERE list_type = %s AND ip_start = UNHEX(%s) AND ip_end = UNHEX(%s) LIMIT 1', // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- COLUMNS is a constant.
				$this->table(),
				$type,
				bin2hex( $cidr->start ),
				bin2hex( $cidr->end )
			),
			ARRAY_A
		);
		return is_array( $row ) ? $row : null;
	}

	/**
	 * Rules whose range contains the address, most specific first.
	 *
	 * @param string $type        List type.
	 * @param string $bin         Packed address.
	 * @param bool   $active_only Exclude expired rules.
	 * @return list<array<string, mixed>>
	 */
	public function find_containing( string $type, string $bin, bool $active_only = true ): array {
		$hex     = bin2hex( $bin );
		$version = 4 === strlen( $bin ) ? 4 : 6;
		if ( $active_only ) {
			$sql = $this->db->prepare(
				'SELECT ' . self::COLUMNS . ' FROM %i WHERE list_type = %s AND ip_version = %d AND ip_start <= UNHEX(%s) AND ip_end >= UNHEX(%s) AND (expires_at IS NULL OR expires_at > %s) ORDER BY prefix DESC, id DESC', // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- COLUMNS is a constant.
				$this->table(),
				$type,
				$version,
				$hex,
				$hex,
				gmdate( 'Y-m-d H:i:s' )
			);
		} else {
			$sql = $this->db->prepare(
				'SELECT ' . self::COLUMNS . ' FROM %i WHERE list_type = %s AND ip_version = %d AND ip_start <= UNHEX(%s) AND ip_end >= UNHEX(%s) ORDER BY prefix DESC, id DESC', // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- COLUMNS is a constant.
				$this->table(),
				$type,
				$version,
				$hex,
				$hex
			);
		}
		$rows = $this->db->get_results( $sql, ARRAY_A ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- Prepared above.
		return is_array( $rows ) ? $rows : array();
	}

	/**
	 * Active ranges for cache compilation.
	 *
	 * @param string $type         List type.
	 * @param bool   $without_auto Leave out automatic administrator entries.
	 * @return list<array{start_hex:string, end_hex:string, expires_at:?string}>
	 */
	public function active_ranges( string $type, bool $without_auto = false ): array {
		$rows = $this->db->get_results(
			$this->db->prepare(
				'SELECT HEX(ip_start) AS start_hex, HEX(ip_end) AS end_hex, expires_at FROM %i WHERE list_type = %s AND (expires_at IS NULL OR expires_at > %s) AND source <> %s',
				$this->table(),
				$type,
				gmdate( 'Y-m-d H:i:s' ),
				$without_auto ? 'admin_auto' : ''
			),
			ARRAY_A
		);
		return is_array( $rows ) ? $rows : array();
	}

	/**
	 * Deletes one rule.
	 *
	 * @param int $id Rule ID.
	 */
	public function delete( int $id ): bool {
		return (bool) $this->db->delete( $this->table(), array( 'id' => $id ), array( '%d' ) );
	}

	/**
	 * Deletes the rule with exactly this list and range.
	 *
	 * @param string $type List type.
	 * @param Cidr   $cidr Range.
	 * @return int Rows deleted.
	 */
	public function delete_exact( string $type, Cidr $cidr ): int {
		return (int) $this->db->query(
			$this->db->prepare(
				'DELETE FROM %i WHERE list_type = %s AND ip_start = UNHEX(%s) AND ip_end = UNHEX(%s)',
				$this->table(),
				$type,
				bin2hex( $cidr->start ),
				bin2hex( $cidr->end )
			)
		);
	}

	/**
	 * Increments the hit counter.
	 *
	 * @param int $id Rule ID.
	 */
	public function increment_hits( int $id ): void {
		$this->db->query(
			$this->db->prepare( 'UPDATE %i SET hits = hits + 1, last_hit_at = %s WHERE id = %d', $this->table(), gmdate( 'Y-m-d H:i:s' ), $id )
		);
	}

	/**
	 * Removes expired rules.
	 *
	 * @return int Rows deleted.
	 */
	public function purge_expired(): int {
		return (int) $this->db->query(
			$this->db->prepare( 'DELETE FROM %i WHERE expires_at IS NOT NULL AND expires_at <= %s', $this->table(), gmdate( 'Y-m-d H:i:s' ) )
		);
	}

	/**
	 * Counts active rules.
	 *
	 * @param string|null $type List type or null for both.
	 */
	public function count_active( ?string $type = null ): int {
		$now = gmdate( 'Y-m-d H:i:s' );
		if ( null === $type ) {
			return (int) $this->db->get_var( $this->db->prepare( 'SELECT COUNT(*) FROM %i WHERE expires_at IS NULL OR expires_at > %s', $this->table(), $now ) );
		}
		return (int) $this->db->get_var(
			$this->db->prepare( 'SELECT COUNT(*) FROM %i WHERE list_type = %s AND (expires_at IS NULL OR expires_at > %s)', $this->table(), $type, $now )
		);
	}

	/**
	 * Paged query for the admin list table and WP-CLI.
	 *
	 * @param array<string, mixed> $args type, search, orderby, order, per_page, page.
	 * @return array{0:list<array<string, mixed>>, 1:int}
	 */
	public function query( array $args ): array {
		$where  = array( '1=1' );
		$params = array( $this->table() );
		$type   = (string) ( $args['type'] ?? '' );
		if ( in_array( $type, array( 'block', 'allow' ), true ) ) {
			$where[]  = 'list_type = %s';
			$params[] = $type;
		}
		$search = trim( (string) ( $args['search'] ?? '' ) );
		if ( '' !== $search ) {
			$cidr = Cidr::parse( $search );
			if ( null !== $cidr ) {
				$where[]  = '(ip_version = %d AND ip_start <= UNHEX(%s) AND ip_end >= UNHEX(%s))';
				$params[] = $cidr->version;
				$params[] = bin2hex( $cidr->start );
				$params[] = bin2hex( $cidr->end );
			} else {
				$like     = '%' . $this->db->esc_like( $search ) . '%';
				$where[]  = '(label LIKE %s OR reason LIKE %s OR source LIKE %s)';
				$params[] = $like;
				$params[] = $like;
				$params[] = $like;
			}
		}
		if ( empty( $args['include_expired'] ) ) {
			$where[]  = '(expires_at IS NULL OR expires_at > %s)';
			$params[] = gmdate( 'Y-m-d H:i:s' );
		}
		$orderby   = in_array( $args['orderby'] ?? '', array( 'created_at', 'expires_at', 'hits', 'label', 'list_type' ), true ) ? (string) $args['orderby'] : 'created_at';
		$order     = 'ASC' === strtoupper( (string) ( $args['order'] ?? 'DESC' ) ) ? 'ASC' : 'DESC';
		$per_page  = max( 1, min( 1000, (int) ( $args['per_page'] ?? 50 ) ) );
		$page      = max( 1, (int) ( $args['page'] ?? 1 ) );
		$where_sql = implode( ' AND ', $where );

		// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQL.NotPrepared -- $where_sql holds only placeholders; ORDER BY values are allowlisted.
		$total = (int) $this->db->get_var( $this->db->prepare( "SELECT COUNT(*) FROM %i WHERE $where_sql", $params ) );
		$rows  = $this->db->get_results(
			$this->db->prepare(
				'SELECT ' . self::COLUMNS . " FROM %i WHERE $where_sql ORDER BY $orderby $order, id DESC LIMIT %d OFFSET %d",
				array_merge( $params, array( $per_page, ( $page - 1 ) * $per_page ) )
			),
			ARRAY_A
		);
		// phpcs:enable
		return array( is_array( $rows ) ? $rows : array(), $total );
	}
}
