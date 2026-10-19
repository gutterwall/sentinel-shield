<?php
/**
 * Randomized policy tests against an independent reference: the effective
 * policy (block minus allow), its CIDR export and the packed lookup the
 * early firewall uses must all agree, address by address, for IPv4 and IPv6.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SentinelShield\Net\Cidr;
use SentinelShield\Net\IpRangeSet;
use SentinelShield\Net\PackedRangeSet;
use SentinelShield\Net\RangeMath;

/**
 * Review 5 (P1). The reference works on small integers: every range lies in a
 * window of WINDOW addresses starting at a base address, and membership is a
 * plain array of booleans, so it shares no code with the byte-string range
 * arithmetic under test. Bases are chosen at the awkward places: the start
 * and end of the address space and just below a carry across several bytes.
 *
 * Iterations: FUZZ_ITERATIONS (default 200); the seed is FUZZ_SEED, or random
 * and printed when a case fails.
 */
final class RangePolicyPropertyTest extends TestCase {

	private const WINDOW = 512;

	/**
	 * Address at base + offset (big-endian addition with carry).
	 *
	 * @param string $base   Packed base address.
	 * @param int    $offset Offset.
	 */
	private static function plus( string $base, int $offset ): string {
		$bytes = array_values( unpack( 'C*', $base ) );
		for ( $i = count( $bytes ) - 1; $i >= 0 && $offset > 0; $i-- ) {
			$sum         = $bytes[ $i ] + ( $offset & 0xff );
			$bytes[ $i ] = $sum & 0xff;
			$offset      = ( $offset >> 8 ) + ( $sum >> 8 );
		}
		return pack( 'C*', ...$bytes );
	}

	/**
	 * Bases to test from, per version: space start, space end, and points
	 * just below carries of one, two and all bytes.
	 *
	 * @return array<string, string>
	 */
	private static function bases( int $version ): array {
		$len = 4 === $version ? 4 : 16;
		return array(
			'space start'      => str_repeat( "\0", $len ),
			'space end'        => str_repeat( "\xff", $len - 2 ) . "\xfe\x00",
			'one-byte carry'   => str_repeat( "\x0a", $len - 1 ) . "\xf0",
			'two-byte carry'   => str_repeat( "\x0b", $len - 2 ) . "\xff\xf0",
			'many-byte carry'  => "\x20" . str_repeat( "\xff", $len - 2 ) . "\x80",
			'random'           => random_bytes( $len ),
		);
	}

	/**
	 * Random ranges inside the window, as [first, last] offsets.
	 *
	 * @return list<array{0:int, 1:int}>
	 */
	private static function random_ranges( int $limit ): array {
		$out = array();
		for ( $i = 0, $n = mt_rand( 0, 8 ); $i < $n; $i++ ) {
			$a     = mt_rand( 0, $limit - 1 );
			$b     = min( $limit - 1, $a + ( mt_rand( 0, 3 ) ? mt_rand( 0, 40 ) : mt_rand( 0, $limit ) ) );
			$out[] = array( $a, $b );
		}
		return $out;
	}

	public function test_policy_export_and_lookup_match_the_reference(): void {
		$seed       = (int) ( getenv( 'FUZZ_SEED' ) ?: random_int( 1, PHP_INT_MAX >> 1 ) );
		// Fewer rounds while coverage is measured (every line is far slower then).
		$measured   = ( function_exists( 'xdebug_code_coverage_started' ) && xdebug_code_coverage_started() ) || ( extension_loaded( 'pcov' ) && ini_get( 'pcov.enabled' ) );
		$iterations = (int) ( getenv( 'FUZZ_ITERATIONS' ) ?: ( $measured ? 12 : 200 ) );
		mt_srand( $seed );
		$checked = 0;
		foreach ( array( 4, 6 ) as $version ) {
			foreach ( self::bases( $version ) as $where => $base ) {
				// The window must not run past the end of the address space.
				$room = 'space end' === $where ? 0x1ff : self::WINDOW;
				for ( $round = 0; $round < max( 1, intdiv( $iterations, 6 ) ); $round++ ) {
					$block = self::random_ranges( $room );
					$allow = self::random_ranges( $room );
					$want  = array_fill( 0, $room, false );
					foreach ( $block as [ $a, $b ] ) {
						for ( $o = $a; $o <= $b; $o++ ) {
							$want[ $o ] = true;
						}
					}
					foreach ( $allow as [ $a, $b ] ) {
						for ( $o = $a; $o <= $b; $o++ ) {
							$want[ $o ] = false;
						}
					}
					$pairs = static fn( array $ranges ): array => array_map( static fn( array $r ): array => array( self::plus( $base, $r[0] ), self::plus( $base, $r[1] ) ), $ranges );
					$set   = RangeMath::subtract( IpRangeSet::from_pairs( $pairs( $block ) ), IpRangeSet::from_pairs( $pairs( $allow ) ) );
					// The export (CIDR labels for server files and Cloudflare) parsed back.
					$cidrs    = RangeMath::cidrs( $set );
					$exported = IpRangeSet::from_strings( $cidrs );
					$packed   = PackedRangeSet::from_set( $set );
					$label    = sprintf( 'IPv%d %s, seed %d, round %d', $version, $where, $seed, $round );
					foreach ( $cidrs as $cidr ) {
						$this->assertNotNull( Cidr::parse( $cidr ), "$label: export produced an invalid CIDR $cidr" );
					}
					for ( $o = 0; $o < $room; $o++ ) {
						$ip = self::plus( $base, $o );
						if ( $want[ $o ] !== $set->contains( $ip ) || $want[ $o ] !== $exported->contains( $ip ) || $want[ $o ] !== $packed->contains( $ip ) ) {
							$this->fail( sprintf( '%s: offset %d (%s) should be %s; policy %s, export %s, lookup %s', $label, $o, inet_ntop( $ip ), $want[ $o ] ? 'blocked' : 'open', var_export( $set->contains( $ip ), true ), var_export( $exported->contains( $ip ), true ), var_export( $packed->contains( $ip ), true ) ) );
						}
					}
					++$checked;
				}
			}
		}
		$this->assertGreaterThan( 0, $checked );
	}

	/**
	 * Whole-space and single-address extremes, where carries and prefix
	 * lengths reach their limits.
	 */
	public function test_extremes(): void {
		foreach ( array( 4 => array( '0.0.0.0/0', '0.0.0.0', '255.255.255.255' ), 6 => array( '::/0', '::', 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff' ) ) as $version => [ $all, $first, $last ] ) {
			$set = RangeMath::subtract( IpRangeSet::from_strings( array( $all ) ), IpRangeSet::from_strings( array( $first, $last ) ) );
			$this->assertFalse( $set->contains( (string) inet_pton( $first ) ), "IPv$version first" );
			$this->assertFalse( $set->contains( (string) inet_pton( $last ) ), "IPv$version last" );
			$this->assertTrue( $set->contains( self::plus( (string) inet_pton( $first ), 1 ) ), "IPv$version second" );
			$cidrs = RangeMath::cidrs( $set );
			$this->assertCount( 4 === $version ? 62 : 254, $cidrs, "IPv$version: the whole space minus both ends" );
			$this->assertTrue( IpRangeSet::from_strings( $cidrs )->contains( self::plus( (string) inet_pton( $first ), 1 ) ) );
			$this->assertSame( array( $all ), RangeMath::cidrs( IpRangeSet::from_strings( array( $all ) ) ) );
		}
	}
}
