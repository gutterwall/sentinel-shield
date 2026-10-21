<?php
/**
 * Deletes in small batches.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Support;

defined( 'ABSPATH' ) || exit;

/**
 * One DELETE over a large table holds locks and grows the undo log for as long
 * as it runs. Small batches keep each statement short; whatever is left after
 * the time budget is deleted by the next maintenance run (which is scheduled
 * soon when a deadline cut the work short).
 */
final class Batch {

	public const SIZE   = 2000;
	public const BUDGET = 10.0;

	/**
	 * Runs a prepared DELETE in batches of SIZE rows. With a Deadline, no batch
	 * is started once it has passed, and the deadline is marked cut when rows
	 * may be left.
	 *
	 * @param \wpdb          $db     Database.
	 * @param string         $delete Prepared DELETE statement without LIMIT.
	 * @param float|Deadline $budget Seconds to spend at most, or a deadline.
	 * @return int Rows deleted.
	 */
	public static function delete( \wpdb $db, string $delete, float|Deadline $budget = self::BUDGET ): int {
		$deadline = $budget instanceof Deadline ? $budget : Deadline::in( $budget );
		$total    = 0;
		while ( ! $deadline->expired() ) {
			$rows   = (int) $db->query( $delete . ' LIMIT ' . self::SIZE ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery -- $delete is prepared by the caller; SIZE is a constant.
			$total += max( 0, $rows );
			if ( self::SIZE !== $rows ) {
				return $total;
			}
		}
		$deadline->cut();
		return $total;
	}
}
