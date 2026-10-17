<?php
/**
 * Progressive lockout engine.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Lockout;

use SentinelShield\Net\IpAddress;

defined( 'ABSPATH' ) || exit;

/**
 * Each lockout of an IP within the repeat window moves it one step up the
 * duration ladder (e.g. 15 min -> 1 h -> 24 h -> permanent). Test-mode offenses
 * are counted separately so testing never escalates real lockouts.
 */
final class LockoutService {

	/**
	 * Time source.
	 *
	 * @var \Closure
	 */
	private \Closure $clock;

	/**
	 * Constructor.
	 *
	 * @param OffenseStore  $offenses     Offense history.
	 * @param BlockWriter   $writer       Creates blocks.
	 * @param \Closure      $is_protected fn( string $ip ): bool, true for allowlisted/server IPs.
	 * @param \Closure      $is_test_mode fn( string $module ): bool.
	 * @param list<int>     $durations    Seconds per step; 0 = permanent.
	 * @param int           $window       Repeat window in seconds.
	 * @param bool          $enabled      Module switch.
	 * @param \Closure|null $clock        fn(): int, defaults to time().
	 */
	public function __construct(
		private OffenseStore $offenses,
		private BlockWriter $writer,
		private \Closure $is_protected,
		private \Closure $is_test_mode,
		private array $durations,
		private int $window,
		private bool $enabled = true,
		?\Closure $clock = null
	) {
		$this->durations = $durations ? array_values( $durations ) : array( 0 );
		$this->clock     = $clock ?? static fn(): int => time();
	}

	/**
	 * Locks out an IP. Returns null when disabled, invalid, or protected.
	 *
	 * @param string $ip     IP text.
	 * @param string $module Triggering module, e.g. "login".
	 * @param string $reason Human-readable reason.
	 */
	public function lock( string $ip, string $module, string $reason ): ?Lockout {
		if ( ! $this->enabled ) {
			return null;
		}
		$bin = IpAddress::to_binary( $ip );
		if ( null === $bin || ( $this->is_protected )( $ip ) ) {
			return null;
		}
		$ip      = (string) IpAddress::from_binary( $bin );
		$now     = ( $this->clock )();
		$is_test = (bool) ( $this->is_test_mode )( $module );
		$prior   = $this->offenses->count_recent( $bin, $now - $this->window, $is_test );
		$this->offenses->record( $bin, $module, $reason, $is_test, $now );

		$step     = min( $prior, count( $this->durations ) - 1 );
		$duration = $this->durations[ $step ];
		$expires  = 0 === $duration ? null : $now + $duration;

		if ( ! $is_test ) {
			$this->writer->block( $ip, $expires, $reason, 'lockout_' . $module );
		}
		return new Lockout( $ip, $step + 1, $duration, $expires, $is_test, $module, $reason );
	}

	/**
	 * Duration (seconds) the next lockout would get after $prior offenses.
	 *
	 * @param int $prior Prior offenses within the window.
	 */
	public function duration_for( int $prior ): int {
		return $this->durations[ min( max( 0, $prior ), count( $this->durations ) - 1 ) ];
	}

	/**
	 * Forgets the escalation history of an IP.
	 *
	 * @param string $ip IP text.
	 */
	public function forget( string $ip ): void {
		$bin = IpAddress::to_binary( $ip );
		if ( null !== $bin ) {
			$this->offenses->clear( $bin );
		}
	}
}
