<?php
/**
 * BlockWriter that records calls.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Tests\Fakes;

use SentinelShield\Lockout\BlockWriter;

final class RecordingBlockWriter implements BlockWriter {

	/** @var list<array{ip:string, expires:?int, reason:string, source:string}> */
	public array $blocks = array();

	public function block( string $ip, ?int $expires, string $reason, string $source ): bool {
		$this->blocks[] = array( 'ip' => $ip, 'expires' => $expires, 'reason' => $reason, 'source' => $source );
		return true;
	}
}
