<?php
/**
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SentinelShield\Net\IpAddress;
use SentinelShield\Net\IpRangeSet;

final class IpRangeSetTest extends TestCase {

	private static function bin( string $ip ): string {
		return (string) IpAddress::to_binary( $ip );
	}

	public function test_matching_mixed_entries(): void {
		$set = IpRangeSet::from_strings( array( '203.0.113.7', '198.51.100.0/24', '2001:db8::/48', 'junk' ) );
		$this->assertTrue( $set->contains( self::bin( '203.0.113.7' ) ) );
		$this->assertFalse( $set->contains( self::bin( '203.0.113.8' ) ) );
		$this->assertTrue( $set->contains( self::bin( '198.51.100.200' ) ) );
		$this->assertTrue( $set->contains( self::bin( '2001:db8:0:ffff::1' ) ) );
		$this->assertFalse( $set->contains( self::bin( '2001:db8:1::1' ) ) );
		$this->assertSame( 3, $set->count() );
	}

	public function test_overlaps_merge(): void {
		$set = IpRangeSet::from_strings( array( '10.0.0.0/8', '10.1.0.0/16', '10.2.3.4', '11.0.0.0/8' ) );
		$this->assertSame( 2, $set->count() );
		$this->assertTrue( $set->contains( self::bin( '10.200.0.1' ) ) );
		$this->assertTrue( $set->contains( self::bin( '11.0.0.1' ) ) );
		$this->assertFalse( $set->contains( self::bin( '12.0.0.1' ) ) );
	}

	public function test_empty_set_and_invalid_lookup(): void {
		$this->assertFalse( IpRangeSet::empty()->contains( self::bin( '1.1.1.1' ) ) );
		$this->assertFalse( IpRangeSet::from_strings( array( '0.0.0.0/0' ) )->contains( 'abc' ) );
	}

	public function test_hex_round_trip(): void {
		$set  = IpRangeSet::from_strings( array( '192.0.2.0/24', '2001:db8::1' ) );
		$copy = IpRangeSet::from_array( $set->to_array() );
		$this->assertTrue( $copy->contains( self::bin( '192.0.2.99' ) ) );
		$this->assertTrue( $copy->contains( self::bin( '2001:db8::1' ) ) );
		$this->assertSame( $set->count(), $copy->count() );
	}

	public function test_from_array_skips_malformed(): void {
		$set = IpRangeSet::from_array( array( 4 => array( array( 'zz', 'zz' ), array( 'c0000200', 'c00002ff' ), 'bad' ) ) );
		$this->assertSame( 1, $set->count() );
	}

	public function test_parse_lines(): void {
		$text = "# office\n203.0.113.7 # desk\r\n\n198.51.100.0/24, 2001:db8::/32\n";
		$this->assertSame( array( '203.0.113.7', '198.51.100.0/24', '2001:db8::/32' ), IpRangeSet::parse_lines( $text ) );
	}

	public function test_large_set_lookup_is_fast(): void {
		$items = array();
		for ( $i = 0; $i < 20000; $i++ ) {
			$items[] = long2ip( 0x0A000000 + ( $i * 4 ) ) . '/31';
		}
		$set   = IpRangeSet::from_strings( $items );
		$start = hrtime( true );
		for ( $i = 0; $i < 1000; $i++ ) {
			$set->contains( self::bin( '10.0.1.' . ( $i % 250 ) ) );
		}
		$per_lookup_ms = ( hrtime( true ) - $start ) / 1e6 / 1000;
		$this->assertLessThan( 0.5, $per_lookup_ms, 'Lookup should be far below the 5 ms budget.' );
	}
}
