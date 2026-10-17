<?php
/**
 * Ranges downloaded from blocklist feeds, one row set per feed.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Repository;

use SentinelShield\Net\Cidr;

defined( 'ABSPATH' ) || exit;

/**
 * Kept apart from the manual rules table so feeds are additive: each feed owns
 * its rows, a refresh replaces only that feed's rows, and the same range listed
 * by several feeds is stored once per feed. Disabling one feed therefore never
 * removes a range that another enabled feed (or an admin) still blocks.
 */
final class FeedRepository {

	private const BATCH = 1000;

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
		return $this->db->base_prefix . 'sentinel_feed_ranges';
	}

	/**
	 * Atomically replaces one feed's ranges (where the storage engine supports transactions).
	 *
	 * @param string     $feed   Feed slug.
	 * @param list<Cidr> $ranges Parsed ranges.
	 * @return int Rows stored.
	 */
	public function replace( string $feed, array $ranges ): int {
		$feed = substr( sanitize_key( $feed ), 0, 32 );
		// phpcs:disable WordPress.DB.DirectDatabaseQuery -- Custom table; callers flush the compiled cache.
		$this->db->query( 'START TRANSACTION' );
		$this->db->query( $this->db->prepare( 'DELETE FROM %i WHERE feed = %s', $this->table(), $feed ) );
		$stored = 0;
		foreach ( array_chunk( $ranges, self::BATCH ) as $chunk ) {
			$values = array();
			$args   = array( $this->table() );
			foreach ( $chunk as $cidr ) {
				$values[] = '(%s, %d, UNHEX(%s), UNHEX(%s), %d)';
				array_push( $args, $feed, $cidr->version, bin2hex( $cidr->start ), bin2hex( $cidr->end ), $cidr->prefix );
			}
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare -- Placeholder list built above.
			$sql = $this->db->prepare( 'INSERT INTO %i (feed, ip_version, ip_start, ip_end, prefix) VALUES ' . implode( ', ', $values ), $args );
			if ( false === $this->db->query( $sql ) ) { // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- Prepared above.
				$this->db->query( 'ROLLBACK' );
				return -1;
			}
			$stored += count( $chunk );
		}
		$this->db->query( 'COMMIT' );
		// phpcs:enable
		return $stored;
	}

	/**
	 * Removes all rows of feeds not in the given list.
	 *
	 * @param list<string> $keep Feed slugs to keep.
	 * @return int Rows deleted.
	 */
	public function delete_except( array $keep ): int {
		// phpcs:disable WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare -- Placeholder list built from count().
		if ( ! $keep ) {
			return (int) $this->db->query( $this->db->prepare( 'DELETE FROM %i', $this->table() ) );
		}
		$placeholders = implode( ', ', array_fill( 0, count( $keep ), '%s' ) );
		return (int) $this->db->query( $this->db->prepare( "DELETE FROM %i WHERE feed NOT IN ($placeholders)", array_merge( array( $this->table() ), $keep ) ) );
		// phpcs:enable
	}

	/**
	 * Hex-encoded ranges of the given feeds, for compiling the lookup set.
	 *
	 * @param list<string> $feeds Feed slugs.
	 * @return list<array{start_hex:string, end_hex:string}>
	 */
	public function ranges( array $feeds ): array {
		if ( ! $feeds ) {
			return array();
		}
		$placeholders = implode( ', ', array_fill( 0, count( $feeds ), '%s' ) );
		// phpcs:disable WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare -- Placeholder list built from count().
		$rows = $this->db->get_results(
			$this->db->prepare( "SELECT HEX(ip_start) AS start_hex, HEX(ip_end) AS end_hex FROM %i WHERE feed IN ($placeholders)", array_merge( array( $this->table() ), $feeds ) ),
			ARRAY_A
		);
		// phpcs:enable
		return is_array( $rows ) ? $rows : array();
	}

	/**
	 * Which of the given feeds list an address, with the matching range.
	 *
	 * Feeds never hold ranges broader than /8 (IPv4) or /16 (IPv6), so the scan
	 * is bounded to the address's own /8 or /16 instead of half the table.
	 *
	 * @param string       $bin   Packed address.
	 * @param list<string> $feeds Feed slugs to consider.
	 * @return list<array{feed:string, ip_version:string, start_hex:string, prefix:string}>
	 */
	public function find_containing( string $bin, array $feeds ): array {
		if ( ! $feeds ) {
			return array();
		}
		$len          = strlen( $bin );
		$keep         = 4 === $len ? 1 : 2;
		$lower        = substr( $bin, 0, $keep ) . str_repeat( "\0", $len - $keep );
		$placeholders = implode( ', ', array_fill( 0, count( $feeds ), '%s' ) );
		// phpcs:disable WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare -- Placeholder list built from count().
		$rows = $this->db->get_results(
			$this->db->prepare(
				"SELECT feed, ip_version, HEX(ip_start) AS start_hex, prefix FROM %i WHERE ip_version = %d AND ip_start BETWEEN UNHEX(%s) AND UNHEX(%s) AND ip_end >= UNHEX(%s) AND feed IN ($placeholders) ORDER BY prefix DESC",
				array_merge( array( $this->table(), 4 === $len ? 4 : 6, bin2hex( $lower ), bin2hex( $bin ), bin2hex( $bin ) ), $feeds )
			),
			ARRAY_A
		);
		// phpcs:enable
		return is_array( $rows ) ? $rows : array();
	}

	/**
	 * Stored row count per feed.
	 *
	 * @return array<string, int>
	 */
	public function counts(): array {
		$rows = $this->db->get_results( $this->db->prepare( 'SELECT feed, COUNT(*) AS n FROM %i GROUP BY feed', $this->table() ), ARRAY_A ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
		$out  = array();
		foreach ( is_array( $rows ) ? $rows : array() as $row ) {
			$out[ (string) $row['feed'] ] = (int) $row['n'];
		}
		return $out;
	}
}
