<?php
/**
 * Lockout result.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Lockout;

defined( 'ABSPATH' ) || exit;

/**
 * Describes a lockout that was applied (or, in test mode, would have been).
 */
final class Lockout {

	/**
	 * Constructor.
	 *
	 * @param string   $ip       IP text.
	 * @param int      $step     1-based escalation step.
	 * @param int      $duration Seconds, 0 = permanent.
	 * @param int|null $expires  Unix expiry, null = permanent.
	 * @param bool     $is_test  Test mode: nothing was enforced.
	 * @param string   $module   Triggering module.
	 * @param string   $reason   Reason.
	 */
	public function __construct(
		public readonly string $ip,
		public readonly int $step,
		public readonly int $duration,
		public readonly ?int $expires,
		public readonly bool $is_test,
		public readonly string $module,
		public readonly string $reason
	) {}

	/**
	 * Whether the block never expires.
	 */
	public function is_permanent(): bool {
		return null === $this->expires;
	}
}
