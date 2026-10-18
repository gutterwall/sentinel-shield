<?php
/**
 * Read-only IP range membership.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Net;

defined( 'ABSPATH' ) || exit;

/**
 * Implemented by in-memory sets and file snapshots.
 */
interface RangeLookup {

	/**
	 * Whether a packed IP (4 or 16 bytes) is in the set.
	 *
	 * @param string $bin Packed IP.
	 */
	public function contains( string $bin ): bool;

	/**
	 * Number of ranges.
	 */
	public function count(): int;
}
