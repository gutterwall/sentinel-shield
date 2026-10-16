<?php
/**
 * In-memory OffenseStore for unit tests.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Tests\Fakes;

use SentinelShield\Lockout\OffenseStore;

final class MemoryOffenseStore implements OffenseStore {

	/** @var list<array{bin:string, module:string, test:bool, time:int}> */
	public array $rows = array();

	public function count_recent( string $bin, int $since, bool $is_test ): int {
		return count(
			array_filter(
				$this->rows,
				static fn( array $r ): bool => $r['bin'] === $bin && $r['test'] === $is_test && $r['time'] >= $since
			)
		);
	}

	public function record( string $bin, string $module, string $reason, bool $is_test, int $time ): void {
		$this->rows[] = array( 'bin' => $bin, 'module' => $module, 'test' => $is_test, 'time' => $time );
	}

	public function clear( string $bin ): void {
		$this->rows = array_values( array_filter( $this->rows, static fn( array $r ): bool => $r['bin'] !== $bin ) );
	}
}
