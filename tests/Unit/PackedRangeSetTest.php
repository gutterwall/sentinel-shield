<?php
/**
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SentinelShield\Net\IpAddress;
use SentinelShield\Net\IpRangeSet;
use SentinelShield\Net\PackedRangeSet;

final class PackedRangeSetTest extends TestCase {

	private static function bin( string $ip ): string {
		return (string) IpAddress::to_binary( $ip );
	}

	public function test_membership_ipv4_and_ipv6(): void {
		$set = PackedRangeSet::from_set( IpRangeSet::from_strings( array( '198.51.100.0/24', '203.0.113.7', '2001:db8::/32' ) ) );
		$this->assertTrue( $set->contains( self::bin( '198.51.100.0' ) ) );
		$this->assertTrue( $set->contains( self::bin( '198.51.100.255' ) ) );
		$this->assertTrue( $set->contains( self::bin( '203.0.113.7' ) ) );
		$this->assertTrue( $set->contains( self::bin( '2001:db8:1::5' ) ) );
		$this->assertFalse( $set->contains( self::bin( '198.51.101.0' ) ) );
		$this->assertFalse( $set->contains( self::bin( '203.0.113.8' ) ) );
		$this->assertFalse( $set->contains( self::bin( '2001:db9::1' ) ) );
		$this->assertFalse( $set->contains( 'bad' ) );
		$this->assertSame( 3, $set->count() );
	}

	public function test_overlapping_inputs_merge(): void {
		$set = PackedRangeSet::from_set( IpRangeSet::from_strings( array( '10.0.0.0/23', '10.0.0.128/25', '10.0.1.0/24' ) ) );
		$this->assertSame( 1, $set->count() );
	}

	public function test_storage_round_trip_and_malformed_input(): void {
		$set  = PackedRangeSet::from_set( IpRangeSet::from_strings( array( '192.0.2.0/24', '2001:db8::/48' ) ) );
		$back = PackedRangeSet::from_storage( $set->to_storage() );
		$this->assertTrue( $back->contains( self::bin( '192.0.2.9' ) ) );
		$this->assertTrue( $back->contains( self::bin( '2001:db8::9' ) ) );
		$this->assertSame( 0, PackedRangeSet::from_storage( array( 4 => '###', 6 => base64_encode( 'odd' ) ) )->count() );
		$this->assertSame( 0, PackedRangeSet::empty()->count() );
	}

	/**
	 * Skipped by the branch coverage run, where tight loops are very slow.
	 *
	 * @group heavy
	 */
	public function test_agrees_with_ip_range_set_on_random_data(): void {
		mt_srand( 42 );
		$items = array();
		for ( $i = 0; $i < 2000; $i++ ) {
			$items[] = sprintf( '%d.%d.%d.0/%d', mt_rand( 1, 223 ), mt_rand( 0, 255 ), mt_rand( 0, 255 ), mt_rand( 16, 32 ) );
		}
		$reference = IpRangeSet::from_strings( $items );
		$packed    = PackedRangeSet::from_set( $reference );
		$this->assertSame( $reference->count(), $packed->count() );
		for ( $i = 0; $i < 20000; $i++ ) {
			$ip = sprintf( '%d.%d.%d.%d', mt_rand( 1, 223 ), mt_rand( 0, 255 ), mt_rand( 0, 255 ), mt_rand( 0, 255 ) );
			$this->assertSame( $reference->contains( self::bin( $ip ) ), $packed->contains( self::bin( $ip ) ), $ip );
		}
	}
}
