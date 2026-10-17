<?php
/**
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SentinelShield\Feeds\FeedParser;
use SentinelShield\Net\Cidr;

final class FeedParserTest extends TestCase {

	private static function fixture( string $name ): string {
		return (string) file_get_contents( dirname( __DIR__ ) . '/fixtures/feeds/' . $name );
	}

	/**
	 * @param list<Cidr> $ranges
	 * @return list<string>
	 */
	private static function labels( array $ranges ): array {
		return array_map( static fn( Cidr $c ): string => $c->to_string(), $ranges );
	}

	public function test_plain_lines_with_comments_and_notes(): void {
		$body   = "# header\n; also a comment\n\n198.51.99.7\n45.148.10.240 # scanner\n45.148.10.0/24\t3\n2a01:4f8::1\n";
		$result = FeedParser::parse( 'lines', $body );
		$this->assertSame( array( '198.51.99.7', '45.148.10.240', '45.148.10.0/24', '2a01:4f8::1' ), self::labels( $result['ranges'] ) );
		$this->assertSame( 0, $result['skipped'] );
	}

	public function test_invalid_entries_are_counted_as_skipped(): void {
		$result = FeedParser::parse( 'lines', "not-an-ip\n999.1.1.1\n8.8.8.8\n" );
		$this->assertSame( array( '8.8.8.8' ), self::labels( $result['ranges'] ) );
		$this->assertSame( 2, $result['skipped'] );
	}

	public function test_duplicates_are_stored_once(): void {
		$result = FeedParser::parse( 'lines', "8.8.8.8\n8.8.8.8\n8.8.8.8/32\n" );
		$this->assertCount( 1, $result['ranges'] );
	}

	public function test_reserved_and_private_ranges_are_dropped(): void {
		$body   = "10.0.0.0/8\n127.0.0.1\n192.168.1.5\n172.20.0.0/16\n100.64.1.1\n169.254.0.1\n224.0.0.0/3\n0.0.0.0/8\n::1\nfe80::1\nfd00::5\n2001:db8::1\n8.8.4.4\n";
		$result = FeedParser::parse( 'lines', $body );
		$this->assertSame( array( '8.8.4.4' ), self::labels( $result['ranges'] ) );
		$this->assertSame( 12, $result['skipped'] );
	}

	public function test_public_range_overlapping_private_space_is_dropped(): void {
		// 172.0.0.0/8 starts and ends in public space but contains 172.16.0.0/12.
		$this->assertFalse( FeedParser::is_acceptable( Cidr::parse( '172.0.0.0/8' ) ) );
		$this->assertTrue( FeedParser::is_acceptable( Cidr::parse( '172.32.0.0/11' ) ) );
	}

	public function test_overly_broad_ranges_are_dropped(): void {
		$this->assertFalse( FeedParser::is_acceptable( Cidr::parse( '1.0.0.0/7' ) ) );
		$this->assertTrue( FeedParser::is_acceptable( Cidr::parse( '1.0.0.0/8' ) ) );
		$this->assertFalse( FeedParser::is_acceptable( Cidr::parse( '2a00::/15' ) ) );
		$this->assertTrue( FeedParser::is_acceptable( Cidr::parse( '2a00::/16' ) ) );
	}

	public function test_spamhaus_json_skips_metadata_line(): void {
		$v4 = FeedParser::parse( 'spamhaus_json', self::fixture( 'spamhaus_v4.json' ) );
		$v6 = FeedParser::parse( 'spamhaus_json', self::fixture( 'spamhaus_v6.json' ) );
		$this->assertCount( 40, $v4['ranges'] );
		$this->assertCount( 10, $v6['ranges'] );
		$this->assertSame( '1.10.16.0/20', $v4['ranges'][0]->to_string() );
		$this->assertSame( 6, $v6['ranges'][0]->version );
		$this->assertSame( 0, $v4['skipped'] );
	}

	public function test_dshield_rows_become_slash_24s(): void {
		$result = FeedParser::parse( 'dshield', self::fixture( 'dshield.txt' ) );
		$this->assertCount( 20, $result['ranges'] );
		foreach ( $result['ranges'] as $cidr ) {
			$this->assertSame( 24, $cidr->prefix );
		}
	}

	public function test_firehol_bogons_are_removed(): void {
		$result = FeedParser::parse( 'lines', self::fixture( 'firehol_level1.netset' ) );
		$labels = self::labels( $result['ranges'] );
		foreach ( array( '10.0.0.0/8', '127.0.0.0/8', '192.168.0.0/16', '172.16.0.0/12', '0.0.0.0/8', '224.0.0.0/3' ) as $bogon ) {
			$this->assertNotContains( $bogon, $labels );
		}
		$this->assertGreaterThan( 40, count( $labels ) );
	}

	public function test_plain_entry(): void {
		$this->assertNull( FeedParser::plain_entry( '   ' ) );
		$this->assertNull( FeedParser::plain_entry( '# 1.2.3.4' ) );
		$this->assertSame( '1.2.3.4', FeedParser::plain_entry( ' 1.2.3.4 ; spam ' ) );
		$this->assertSame( '1.2.3.0/24', FeedParser::plain_entry( "1.2.3.0/24\tnote" ) );
	}
}
