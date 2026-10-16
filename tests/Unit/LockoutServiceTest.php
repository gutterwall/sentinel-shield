<?php
/**
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SentinelShield\Lockout\LockoutService;
use SentinelShield\Tests\Fakes\MemoryOffenseStore;
use SentinelShield\Tests\Fakes\RecordingBlockWriter;

final class LockoutServiceTest extends TestCase {

	private const LADDER = array( 900, 3600, 86400, 0 );
	private const WINDOW = 7 * 86400;

	private MemoryOffenseStore $store;
	private RecordingBlockWriter $writer;
	private int $now = 1700000000;
	private bool $test_mode = false;
	/** @var list<string> */
	private array $protected = array();

	protected function setUp(): void {
		$this->store  = new MemoryOffenseStore();
		$this->writer = new RecordingBlockWriter();
	}

	private function service( bool $enabled = true, array $ladder = self::LADDER ): LockoutService {
		return new LockoutService(
			$this->store,
			$this->writer,
			fn( string $ip ): bool => in_array( $ip, $this->protected, true ),
			fn( string $module ): bool => $this->test_mode,
			$ladder,
			self::WINDOW,
			$enabled,
			fn(): int => $this->now
		);
	}

	public function test_progressive_ladder(): void {
		$svc      = $this->service();
		$expected = array( 900, 3600, 86400, 0 );
		foreach ( $expected as $i => $duration ) {
			$lock = $svc->lock( '203.0.113.10', 'login', 'too many failures' );
			$this->assertSame( $i + 1, $lock->step );
			$this->assertSame( $duration, $lock->duration );
			$this->assertSame( 0 === $duration ? null : $this->now + $duration, $lock->expires );
			$this->now += 60;
		}
		$this->assertCount( 4, $this->writer->blocks );
		$this->assertTrue( $svc->lock( '203.0.113.10', 'login', 'again' )->is_permanent(), 'Steps past the ladder stay permanent.' );
		$this->assertSame( 'lockout_login', $this->writer->blocks[0]['source'] );
	}

	public function test_offenses_expire_after_window(): void {
		$svc = $this->service();
		$svc->lock( '203.0.113.10', 'login', 'x' );
		$this->now += self::WINDOW + 1;
		$this->assertSame( 1, $svc->lock( '203.0.113.10', 'login', 'x' )->step );
	}

	public function test_ips_are_tracked_independently_and_normalized(): void {
		$svc = $this->service();
		$svc->lock( '2001:db8::1', '404', 'x' );
		$this->assertSame( 2, $svc->lock( '2001:0db8:0:0::1', '404', 'x' )->step );
		$this->assertSame( 1, $svc->lock( '2001:db8::2', '404', 'x' )->step );
		$this->assertSame( '2001:db8::1', $this->writer->blocks[1]['ip'] );
	}

	public function test_protected_ip_is_never_locked(): void {
		$this->protected = array( '198.51.100.5' );
		$this->assertNull( $this->service()->lock( '198.51.100.5', 'login', 'x' ) );
		$this->assertSame( array(), $this->writer->blocks );
		$this->assertSame( array(), $this->store->rows );
	}

	public function test_test_mode_logs_but_does_not_block_or_escalate_real_lockouts(): void {
		$this->test_mode = true;
		$svc             = $this->service();
		$first           = $svc->lock( '203.0.113.10', 'login', 'x' );
		$second          = $svc->lock( '203.0.113.10', 'login', 'x' );
		$this->assertTrue( $first->is_test );
		$this->assertSame( 2, $second->step, 'Test mode still shows the escalation it would apply.' );
		$this->assertSame( array(), $this->writer->blocks );

		$this->test_mode = false;
		$real            = $svc->lock( '203.0.113.10', 'login', 'x' );
		$this->assertSame( 1, $real->step, 'Test offenses must not escalate real lockouts.' );
		$this->assertCount( 1, $this->writer->blocks );
	}

	public function test_disabled_and_invalid(): void {
		$this->assertNull( $this->service( false )->lock( '203.0.113.10', 'login', 'x' ) );
		$this->assertNull( $this->service()->lock( 'not-an-ip', 'login', 'x' ) );
	}

	public function test_short_ladder_and_forget(): void {
		$svc = $this->service( true, array( 600 ) );
		$svc->lock( '203.0.113.10', 'waf', 'x' );
		$this->assertSame( 600, $svc->lock( '203.0.113.10', 'waf', 'x' )->duration, 'Last step repeats.' );
		$svc->forget( '203.0.113.10' );
		$this->assertSame( 1, $svc->lock( '203.0.113.10', 'waf', 'x' )->step );
		$this->assertSame( 600, $svc->duration_for( 99 ) );
	}

	public function test_permanent_first_step(): void {
		$lock = $this->service( true, array( 0 ) )->lock( '203.0.113.10', 'login', 'x' );
		$this->assertTrue( $lock->is_permanent() );
		$this->assertNull( $this->writer->blocks[0]['expires'] );
	}
}
