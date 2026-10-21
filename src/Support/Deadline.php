<?php
/**
 * A point in time that bounded work must not run past.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Support;

defined( 'ABSPATH' ) || exit;

/**
 * Passed through work that has a time budget (maintenance, audit delivery),
 * so every step can ask how much time is left instead of each keeping its own
 * clock. Rules for the steps:
 *
 * - nothing new is started once the deadline has passed;
 * - work that cannot be interrupted (a policy build) starts only if it is
 *   expected to fit;
 * - network timeouts are capped to the time left;
 * - a step that stops with work left calls cut(), and the caller schedules a
 *   continuation.
 *
 * A step already running (one database batch, one HTTP request) can end a
 * little after the deadline; batches are small and timeouts capped, so that
 * overrun is bounded.
 */
final class Deadline {

	/**
	 * Whether a step stopped with work left.
	 *
	 * @var bool
	 */
	private bool $cut = false;

	/**
	 * Constructor.
	 *
	 * @param float $at Unix time (microtime) of the deadline.
	 */
	public function __construct( private float $at ) {}

	/**
	 * A deadline $seconds from now.
	 *
	 * @param float $seconds Seconds (INF for none).
	 */
	public static function in( float $seconds ): self {
		return new self( microtime( true ) + $seconds );
	}

	/**
	 * Seconds left (0 when passed).
	 */
	public function left(): float {
		return max( 0.0, $this->at - microtime( true ) );
	}

	/**
	 * Whether the deadline has passed.
	 */
	public function expired(): bool {
		return $this->left() <= 0.0;
	}

	/**
	 * Whether work expected to take $seconds fits in the time left.
	 *
	 * @param float $seconds Expected duration.
	 */
	public function allows( float $seconds ): bool {
		return $this->left() >= $seconds;
	}

	/**
	 * A network timeout: $cap seconds at most, never past the deadline; 0 when
	 * less than $min seconds are left (too little for a request: do not send).
	 *
	 * @param int $cap Usual timeout.
	 * @param int $min Shortest useful timeout.
	 */
	public function timeout( int $cap, int $min = 2 ): int {
		$left = (int) floor( min( (float) $cap, $this->left() ) );
		return $left >= $min ? $left : 0;
	}

	/**
	 * Notes that a step stopped with work left.
	 */
	public function cut(): void {
		$this->cut = true;
	}

	/**
	 * Whether any step stopped with work left.
	 */
	public function was_cut(): bool {
		return $this->cut;
	}
}
