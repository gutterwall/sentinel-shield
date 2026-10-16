<?php
/**
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SentinelShield\Net\IpAddress;

final class IpAddressTest extends TestCase {

	public function test_ipv4_packs_to_four_bytes(): void {
		$this->assertSame( "\xC0\x00\x02\x01", IpAddress::to_binary( '192.0.2.1' ) );
	}

	public function test_ipv6_packs_to_sixteen_bytes(): void {
		$this->assertSame( 16, strlen( (string) IpAddress::to_binary( '2001:db8::1' ) ) );
	}

	public function test_ipv4_mapped_ipv6_collapses_to_ipv4(): void {
		$this->assertSame( IpAddress::to_binary( '192.0.2.1' ), IpAddress::to_binary( '::ffff:192.0.2.1' ) );
		$this->assertSame( '192.0.2.1', IpAddress::normalize( '::ffff:c000:0201' ) );
	}

	/**
	 * @dataProvider invalid_provider
	 */
	public function test_invalid_input_returns_null( string $input ): void {
		$this->assertNull( IpAddress::to_binary( $input ) );
	}

	/** @return array<string, array{0:string}> */
	public static function invalid_provider(): array {
		return array(
			'empty'        => array( '' ),
			'text'         => array( 'not-an-ip' ),
			'octet range'  => array( '256.1.1.1' ),
			'short'        => array( '1.2.3' ),
			'cidr'         => array( '10.0.0.0/8' ),
			'double colon' => array( '2001:db8::1::2' ),
			'injection'    => array( "1.2.3.4' OR 1=1" ),
			'spaces'       => array( '1.2.3.4 5.6.7.8' ),
		);
	}

	public function test_tolerates_ports_brackets_and_zone_ids(): void {
		$this->assertSame( '192.0.2.1', IpAddress::normalize( '192.0.2.1:8080' ) );
		$this->assertSame( '2001:db8::1', IpAddress::normalize( '[2001:db8::1]:443' ) );
		$this->assertSame( 'fe80::1', IpAddress::normalize( 'fe80::1%eth0' ) );
		$this->assertSame( '192.0.2.1', IpAddress::normalize( '  192.0.2.1  ' ) );
	}

	public function test_normalizes_ipv6_text(): void {
		$this->assertSame( '2001:db8::1', IpAddress::normalize( '2001:0DB8:0000:0000:0000:0000:0000:0001' ) );
	}

	public function test_round_trip(): void {
		foreach ( array( '0.0.0.0', '255.255.255.255', '10.1.2.3', '::', '::1', '2001:db8:85a3::8a2e:370:7334' ) as $ip ) {
			$this->assertSame( $ip, IpAddress::from_binary( (string) IpAddress::to_binary( $ip ) ) );
		}
		$this->assertNull( IpAddress::from_binary( 'abc' ) );
	}

	public function test_private_detection(): void {
		foreach ( array( '10.0.0.1', '172.16.5.4', '192.168.1.1', '127.0.0.1', '100.64.0.1', '::1', 'fd00::1' ) as $ip ) {
			$this->assertTrue( IpAddress::is_private( (string) IpAddress::to_binary( $ip ) ), $ip );
		}
		foreach ( array( '8.8.8.8', '172.32.0.1', '2001:4860::8888' ) as $ip ) {
			$this->assertFalse( IpAddress::is_private( (string) IpAddress::to_binary( $ip ) ), $ip );
		}
	}
}
