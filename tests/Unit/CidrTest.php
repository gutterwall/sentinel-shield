<?php
/**
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SentinelShield\Net\Cidr;
use SentinelShield\Net\IpAddress;

final class CidrTest extends TestCase {

	private static function bin( string $ip ): string {
		return (string) IpAddress::to_binary( $ip );
	}

	public function test_ipv4_network_bounds(): void {
		$c = Cidr::parse( '192.168.1.0/24' );
		$this->assertNotNull( $c );
		$this->assertSame( '192.168.1.0', IpAddress::from_binary( $c->start ) );
		$this->assertSame( '192.168.1.255', IpAddress::from_binary( $c->end ) );
		$this->assertSame( 24, $c->prefix );
		$this->assertSame( 4, $c->version );
	}

	public function test_host_bits_are_masked(): void {
		$c = Cidr::parse( '192.168.1.77/24' );
		$this->assertSame( '192.168.1.0/24', $c->to_string() );
	}

	public function test_single_ip_is_host_range(): void {
		$c = Cidr::parse( '10.0.0.5' );
		$this->assertTrue( $c->is_single() );
		$this->assertSame( '10.0.0.5', $c->to_string() );
		$this->assertTrue( $c->contains( self::bin( '10.0.0.5' ) ) );
		$this->assertFalse( $c->contains( self::bin( '10.0.0.6' ) ) );
	}

	public function test_non_octet_prefix(): void {
		$c = Cidr::parse( '10.0.0.0/13' );
		$this->assertSame( '10.7.255.255', IpAddress::from_binary( $c->end ) );
		$this->assertTrue( $c->contains( self::bin( '10.7.1.1' ) ) );
		$this->assertFalse( $c->contains( self::bin( '10.8.0.0' ) ) );
	}

	public function test_zero_prefix_matches_everything_in_family(): void {
		$c = Cidr::parse( '0.0.0.0/0' );
		$this->assertTrue( $c->contains( self::bin( '255.255.255.255' ) ) );
		$this->assertFalse( $c->contains( self::bin( '::1' ) ) );
	}

	public function test_ipv6_ranges(): void {
		$c = Cidr::parse( '2001:db8::/32' );
		$this->assertTrue( $c->contains( self::bin( '2001:db8:ffff:ffff::1' ) ) );
		$this->assertFalse( $c->contains( self::bin( '2001:db9::' ) ) );
		$this->assertSame( 6, $c->version );

		$c64 = Cidr::parse( '2001:db8:1:2::/64' );
		$this->assertTrue( $c64->contains( self::bin( '2001:db8:1:2:ffff:ffff:ffff:ffff' ) ) );
		$this->assertFalse( $c64->contains( self::bin( '2001:db8:1:3::' ) ) );
	}

	public function test_families_never_cross_match(): void {
		$this->assertFalse( Cidr::parse( '::/0' )->contains( self::bin( '1.2.3.4' ) ) );
	}

	public function test_ipv4_mapped_network(): void {
		$c = Cidr::parse( '::ffff:10.0.0.0/104' );
		$this->assertSame( '10.0.0.0/8', $c->to_string() );
		$this->assertNull( Cidr::parse( '::ffff:10.0.0.0/64' ) );
	}

	/**
	 * @dataProvider invalid_provider
	 */
	public function test_invalid_input( string $input ): void {
		$this->assertNull( Cidr::parse( $input ) );
	}

	/** @return array<string, array{0:string}> */
	public static function invalid_provider(): array {
		return array(
			'empty'          => array( '' ),
			'prefix too big' => array( '1.2.3.4/33' ),
			'v6 too big'     => array( '2001:db8::/129' ),
			'negative'       => array( '1.2.3.4/-1' ),
			'text prefix'    => array( '1.2.3.4/abc' ),
			'empty prefix'   => array( '1.2.3.4/' ),
			'garbage'        => array( 'example.com' ),
			'two slashes'    => array( '1.2.3.4/24/8' ),
		);
	}

	public function test_boundaries_inclusive(): void {
		$c = Cidr::parse( '198.51.100.0/30' );
		$this->assertTrue( $c->contains( self::bin( '198.51.100.0' ) ) );
		$this->assertTrue( $c->contains( self::bin( '198.51.100.3' ) ) );
		$this->assertFalse( $c->contains( self::bin( '198.51.100.4' ) ) );
		$this->assertFalse( $c->contains( self::bin( '198.51.99.255' ) ) );
	}
}
