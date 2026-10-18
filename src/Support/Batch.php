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
 * the time budget is deleted by the next maintenance run.
 */
final class Batch {

	public const SIZE   = 2000;
	public const BUDGET = 10.0;

	/**
	 * Runs a prepared DELETE in batches of SIZE rows.
	 *
	 * @param \wpdb  $db     Database.
	 * @param string $delete Prepared DELETE statement without LIMIT.
	 * @param float  $budget Seconds to spend at most.
	 * @return int Rows deleted.
	 */
	public static function delete( \wpdb $db, string $delete, float $budget = self::BUDGET ): int {
		$total = 0;
		$until = microtime( true ) + $budget;
		do {
			$rows   = (int) $db->query( $delete . ' LIMIT ' . self::SIZE ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery -- $delete is prepared by the caller; SIZE is a constant.
			$total += max( 0, $rows );
		} while ( self::SIZE === $rows && microtime( true ) < $until );
		return $total;
	}
}
