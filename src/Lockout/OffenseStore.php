<?php
/**
 * Offense history contract.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Lockout;

defined( 'ABSPATH' ) || exit;

/**
 * Storage for lockout history, separated so the lockout logic is testable without a database.
 */
interface OffenseStore {

	/**
	 * Offenses for an IP since a time.
	 *
	 * @param string $bin     Packed IP.
	 * @param int    $since   Unix time.
	 * @param bool   $is_test Count test-mode offenses.
	 */
	public function count_recent( string $bin, int $since, bool $is_test ): int;

	/**
	 * Records an offense.
	 *
	 * @param string $bin     Packed IP.
	 * @param string $module  Module slug.
	 * @param string $reason  Reason.
	 * @param bool   $is_test Test mode.
	 * @param int    $time    Unix time.
	 */
	public function record( string $bin, string $module, string $reason, bool $is_test, int $time ): void;

	/**
	 * Forgets all offenses for an IP.
	 *
	 * @param string $bin Packed IP.
	 */
	public function clear( string $bin ): void;
}
