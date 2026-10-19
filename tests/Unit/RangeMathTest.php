<?php
/**
 * Range subtraction and CIDR splitting.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SentinelShield\Net\IpRangeSet;
use SentinelShield\Net\RangeMath;

final class RangeMathTest extends TestCase {

	public function test_subtracting_one_address_from_a_slash24(): void {
		$out = RangeMath::cidrs( RangeMath::subtract( IpRangeSet::from_strings( array( '203.0.113.0/24' ) ), IpRangeSet::from_strings( array( '203.0.113.7' ) ) ) );
		$this->assertSame( array( '203.0.113.0/30', '203.0.113.4/31', '203.0.113.6', '203.0.113.8/29', '203.0.113.16/28', '203.0.113.32/27', '203.0.113.64/26', '203.0.113.128/25' ), $out );
	}

	public function test_edges_and_full_removal(): void {
		$this->assertSame( array(), RangeMath::cidrs( RangeMath::subtract( IpRangeSet::from_strings( array( '10.0.0.0/8' ) ), IpRangeSet::from_strings( array( '0.0.0.0/0' ) ) ) ) );
		$this->assertSame( array( '0.0.0.1', '0.0.0.2/31', '0.0.0.4/30', '0.0.0.8/29', '0.0.0.16/28', '0.0.0.32/27', '0.0.0.64/26', '0.0.0.128/25' ), RangeMath::cidrs( RangeMath::subtract( IpRangeSet::from_strings( array( '0.0.0.0/24' ) ), IpRangeSet::from_strings( array( '0.0.0.0' ) ) ) ) );
		$this->assertSame( array( '255.255.255.254' ), RangeMath::cidrs( RangeMath::subtract( IpRangeSet::from_strings( array( '255.255.255.254/31' ) ), IpRangeSet::from_strings( array( '255.255.255.255' ) ) ) ) );
		$this->assertSame( array( '198.51.100.0/24' ), RangeMath::cidrs( RangeMath::subtract( IpRangeSet::from_strings( array( '198.51.100.0/24' ) ), IpRangeSet::from_strings( array( '203.0.113.0/24' ) ) ) ), 'no overlap: unchanged' );
	}

	public function test_ipv6_and_mixed(): void {
		$out = RangeMath::cidrs( RangeMath::subtract( IpRangeSet::from_strings( array( '2001:db8::/126', '192.0.2.0/30' ) ), IpRangeSet::from_strings( array( '2001:db8::2', '192.0.2.0/31' ) ) ) );
		$this->assertSame( array( '192.0.2.2/31', '2001:db8::/127', '2001:db8::3' ), $out );
		$big = RangeMath::cidrs( RangeMath::subtract( IpRangeSet::from_strings( array( '::/0' ) ), IpRangeSet::from_strings( array( '2001:db8::1' ) ) ) );
		$this->assertCount( 128, $big, 'all of IPv6 minus one address is 128 blocks' );
		$set = IpRangeSet::from_strings( $big );
		$this->assertFalse( $set->contains( (string) inet_pton( '2001:db8::1' ) ) );
		$this->assertTrue( $set->contains( (string) inet_pton( '2001:db8::2' ) ) );
		$this->assertTrue( $set->contains( (string) inet_pton( 'ffff::1' ) ) );
	}

	public function test_matches_a_brute_force_answer_on_random_sets(): void {
		mt_srand( 8102 );
		$ip = static fn( int $n ): string => pack( 'N', ( 10 << 24 ) + $n );
		for ( $round = 0; $round < 200; $round++ ) {
			$make = static function ( int $count ) use ( $ip ): array {
				$pairs = array();
				for ( $i = 0; $i < $count; $i++ ) {
					$a       = mt_rand( 0, 255 );
					$b       = min( 255, $a + mt_rand( 0, 40 ) );
					$pairs[] = array( $ip( $a ), $ip( $b ) );
				}
				return $pairs;
			};
			$from  = IpRangeSet::from_pairs( $make( mt_rand( 0, 6 ) ) );
			$minus = IpRangeSet::from_pairs( $make( mt_rand( 0, 6 ) ) );
			$got   = RangeMath::subtract( $from, $minus );
			for ( $n = 0; $n <= 255; $n++ ) {
				$want = $from->contains( $ip( $n ) ) && ! $minus->contains( $ip( $n ) );
				$this->assertSame( $want, $got->contains( $ip( $n ) ), "round $round, address $n" );
			}
		}
	}

	public function test_large_sets_are_subtracted_quickly(): void {
		$block = array();
		$allow = array();
		for ( $i = 0; $i < 20000; $i++ ) {
			$block[] = long2ip( ( 11 << 24 ) + $i * 256 ) . '/24';
			$allow[] = long2ip( ( 11 << 24 ) + $i * 256 + 7 );
		}
		$from  = IpRangeSet::from_strings( $block );
		$minus = IpRangeSet::from_strings( $allow );
		$start = microtime( true );
		$out   = RangeMath::subtract( $from, $minus );
		$this->assertLessThan( 2.0, microtime( true ) - $start, '20,000 ranges minus 20,000 exemptions' );
		$this->assertSame( 40000, $out->count() );
	}
}
