<?php
/**
 * Security event log persistence.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Repository;

use SentinelShield\Http\Request;
use SentinelShield\Net\IpAddress;

use SentinelShield\Support\Batch;

defined( 'ABSPATH' ) || exit;

/**
 * Append-only event log (blocks, would-blocks, lockouts, unlocks, config changes).
 */
final class EventRepository {

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
		return $this->db->base_prefix . 'sentinel_events';
	}

	/**
	 * Records an event.
	 *
	 * @param string               $event Event type, e.g. "blocked".
	 * @param array<string, mixed> $data  ip, module, reason, uri, user_agent, user_id, is_test, context.
	 */
	public function log( string $event, array $data = array() ): void {
		$ip  = (string) ( $data['ip'] ?? '' );
		$bin = IpAddress::to_binary( $ip );
		$ctx = isset( $data['context'] ) ? wp_json_encode( $data['context'] ) : '';
		$this->db->query(
			$this->db->prepare(
				"INSERT INTO %i (created_at, ip, ip_text, event, module, reason, uri, user_agent, user_id, is_test, context)
				VALUES (%s, NULLIF(UNHEX(%s), ''), %s, %s, %s, %s, %s, %s, %d, %d, %s)",
				$this->table(),
				gmdate( 'Y-m-d H:i:s' ),
				null === $bin ? '' : bin2hex( $bin ),
				null === $bin ? '' : (string) IpAddress::from_binary( $bin ),
				substr( sanitize_key( $event ), 0, 32 ),
				substr( sanitize_key( (string) ( $data['module'] ?? '' ) ), 0, 32 ),
				mb_substr( (string) ( $data['reason'] ?? '' ), 0, 255 ),
				substr( Request::redact_uri( (string) ( $data['uri'] ?? '' ) ), 0, 2048 ),
				substr( (string) ( $data['user_agent'] ?? '' ), 0, 512 ),
				(int) ( $data['user_id'] ?? 0 ),
				empty( $data['is_test'] ) ? 0 : 1,
				(string) $ctx
			)
		);
		/**
		 * After a security event is stored (used by the remote audit export).
		 *
		 * @param int                  $id    Row ID.
		 * @param string               $event Event type.
		 * @param array<string, mixed> $data  Event data.
		 */
		do_action( 'sentinel_shield_event_logged', (int) $this->db->insert_id, $event, $data );
	}

	/**
	 * Paged, filtered events, newest first.
	 *
	 * @param array<string, mixed> $filters event, ip, module, is_test, per_page, page.
	 * @return array{0:list<array<string, mixed>>, 1:int}
	 */
	public function query( array $filters = array() ): array {
		$where  = array( '1=1' );
		$params = array( $this->table() );
		if ( ! empty( $filters['event'] ) ) {
			$where[]  = 'event = %s';
			$params[] = sanitize_key( (string) $filters['event'] );
		}
		if ( ! empty( $filters['module'] ) ) {
			$where[]  = 'module = %s';
			$params[] = sanitize_key( (string) $filters['module'] );
		}
		if ( ! empty( $filters['ip'] ) ) {
			$bin = IpAddress::to_binary( (string) $filters['ip'] );
			if ( null !== $bin ) {
				$where[]  = 'ip = UNHEX(%s)';
				$params[] = bin2hex( $bin );
			}
		}
		if ( isset( $filters['is_test'] ) && '' !== $filters['is_test'] ) {
			$where[]  = 'is_test = %d';
			$params[] = (int) $filters['is_test'];
		}
		$per_page  = max( 1, min( 1000, (int) ( $filters['per_page'] ?? 50 ) ) );
		$page      = max( 1, (int) ( $filters['page'] ?? 1 ) );
		$where_sql = implode( ' AND ', $where );

		// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQL.NotPrepared -- $where_sql holds only placeholders.
		$total = (int) $this->db->get_var( $this->db->prepare( "SELECT COUNT(*) FROM %i WHERE $where_sql", $params ) );
		$rows  = $this->db->get_results(
			$this->db->prepare(
				"SELECT id, created_at, ip_text, event, module, reason, uri, user_agent, user_id, is_test, context FROM %i WHERE $where_sql ORDER BY id DESC LIMIT %d OFFSET %d",
				array_merge( $params, array( $per_page, ( $page - 1 ) * $per_page ) )
			),
			ARRAY_A
		);
		// phpcs:enable
		return array( is_array( $rows ) ? $rows : array(), $total );
	}

	/**
	 * Counts events of the given types since a UTC timestamp.
	 *
	 * @param list<string> $events Event types.
	 * @param int          $since  Unix time.
	 */
	public function count_since( array $events, int $since ): int {
		if ( ! $events ) {
			return 0;
		}
		$placeholders = implode( ', ', array_fill( 0, count( $events ), '%s' ) );
		// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare -- Placeholder list built from count().
		return (int) $this->db->get_var(
			$this->db->prepare(
				"SELECT COUNT(*) FROM %i WHERE event IN ($placeholders) AND created_at >= %s",
				array_merge( array( $this->table() ), array_map( 'sanitize_key', $events ), array( gmdate( 'Y-m-d H:i:s', $since ) ) )
			)
		);
		// phpcs:enable
	}

	/**
	 * Most frequent IPs for the given events since a timestamp.
	 *
	 * @param list<string> $events Event types.
	 * @param int          $since  Unix time.
	 * @param int          $limit  Max rows.
	 * @return list<array{ip_text:string, hits:string}>
	 */
	public function top_ips( array $events, int $since, int $limit = 10 ): array {
		if ( ! $events ) {
			return array();
		}
		$placeholders = implode( ', ', array_fill( 0, count( $events ), '%s' ) );
		// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare -- Placeholder list built from count().
		$rows = $this->db->get_results(
			$this->db->prepare(
				"SELECT ip_text, COUNT(*) AS hits FROM %i WHERE event IN ($placeholders) AND created_at >= %s AND ip_text <> '' GROUP BY ip_text ORDER BY hits DESC LIMIT %d",
				array_merge( array( $this->table() ), array_map( 'sanitize_key', $events ), array( gmdate( 'Y-m-d H:i:s', $since ), $limit ) )
			),
			ARRAY_A
		);
		// phpcs:enable
		return is_array( $rows ) ? $rows : array();
	}

	/**
	 * Deletes events older than N days. Events after $keep_after (not yet
	 * delivered to the remote audit log) are kept, up to $hard_days.
	 *
	 * @param int      $days       Retention.
	 * @param int|null $keep_after Last delivered event ID, or null to keep nothing extra.
	 * @param int      $hard_days  Undelivered events are kept at most this long.
	 * @return int Rows deleted.
	 */
	public function prune( int $days, ?int $keep_after = null, int $hard_days = 90 ): int {
		$cutoff = gmdate( 'Y-m-d H:i:s', time() - ( max( 1, $days ) * DAY_IN_SECONDS ) );
		if ( null === $keep_after ) {
			return Batch::delete( $this->db, $this->db->prepare( 'DELETE FROM %i WHERE created_at < %s', $this->table(), $cutoff ) );
		}
		$hard = gmdate( 'Y-m-d H:i:s', time() - ( max( $days, $hard_days ) * DAY_IN_SECONDS ) );
		return Batch::delete( $this->db, $this->db->prepare( 'DELETE FROM %i WHERE created_at < %s AND ( id <= %d OR created_at < %s )', $this->table(), $cutoff, $keep_after, $hard ) );
	}

	/**
	 * Number of events after an ID that are older than N days (about to be
	 * pruned although never delivered).
	 *
	 * @param int $after ID.
	 * @param int $days  Age.
	 */
	public function count_undelivered_older( int $after, int $days ): int {
		return (int) $this->db->get_var( $this->db->prepare( 'SELECT COUNT(*) FROM %i WHERE id > %d AND created_at < %s', $this->table(), $after, gmdate( 'Y-m-d H:i:s', time() - $days * DAY_IN_SECONDS ) ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Live count.
	}
}
