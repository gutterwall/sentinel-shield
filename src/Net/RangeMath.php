<?php
/**
 * Set arithmetic on IP ranges.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Net;

defined( 'ABSPATH' ) || exit;

/**
 * Subtracts one range set from another and splits ranges into CIDR blocks.
 * Used to turn "block these, except those allowed" into plain deny rules for
 * web servers and CDNs, which have no notion of an allowlist that wins.
 * Addresses are big-endian binary strings (4 or 16 bytes).
 */
final class RangeMath {

	/**
	 * $from minus $minus, in one sweep over both sorted, merged lists
	 * (O(n + m) instead of comparing every range with every exemption).
	 *
	 * @param IpRangeSet $from  Ranges.
	 * @param IpRangeSet $minus Ranges to remove.
	 */
	public static function subtract( IpRangeSet $from, IpRangeSet $minus ): IpRangeSet {
		$out = array();
		foreach ( array( 4, 6 ) as $version ) {
			$cuts  = $minus->pairs( $version );
			$count = count( $cuts );
			$j     = 0;
			foreach ( $from->pairs( $version ) as [ $start, $end ] ) {
				// Exemptions ending before this range cannot touch it or any later one.
				while ( $j < $count && strcmp( $cuts[ $j ][1], $start ) < 0 ) {
					++$j;
				}
				$cursor = $start;
				$open   = true;
				for ( $k = $j; $k < $count; $k++ ) {
					[ $cs, $ce ] = $cuts[ $k ];
					if ( strcmp( $cs, $end ) > 0 ) {
						break;
					}
					if ( strcmp( $cs, $cursor ) > 0 ) {
						$out[] = array( $cursor, self::step( $cs, -1 ) );
					}
					if ( strcmp( $ce, $end ) >= 0 ) {
						$open = false;
						break;
					}
					if ( strcmp( $ce, $cursor ) >= 0 ) {
						$cursor = self::step( $ce, 1 );
					}
				}
				if ( $open ) {
					$out[] = array( $cursor, $end );
				}
			}
		}
		return IpRangeSet::from_pairs( $out );
	}

	/**
	 * The smallest list of CIDR blocks that exactly covers a set, as text
	 * (single addresses without a prefix).
	 *
	 * @param IpRangeSet $set Ranges.
	 * @return list<string>
	 */
	public static function cidrs( IpRangeSet $set ): array {
		$out = array();
		foreach ( array( 4, 6 ) as $version ) {
			foreach ( $set->pairs( $version ) as [ $start, $end ] ) {
				foreach ( self::range_cidrs( $start, $end ) as $cidr ) {
					$out[] = $cidr;
				}
			}
		}
		return $out;
	}

	/**
	 * CIDR blocks covering start..end.
	 *
	 * @param string $start First address.
	 * @param string $end   Last address.
	 * @return list<string>
	 */
	public static function range_cidrs( string $start, string $end ): array {
		$bits  = 8 * strlen( $start );
		$out   = array();
		$guard = 0;
		while ( strcmp( $start, $end ) <= 0 && $guard++ < 300 ) {
			// The largest aligned block at $start that does not pass $end.
			$last = $start;
			for ( $host = self::trailing_zeros( $start, $bits ); $host >= 0; $host-- ) {
				$last = self::fill( $start, $host );
				if ( strcmp( $last, $end ) <= 0 ) {
					break;
				}
			}
			$prefix = $bits - $host;
			$text   = (string) inet_ntop( $start );
			$out[]  = $prefix === $bits ? $text : $text . '/' . $prefix;
			if ( str_repeat( "\xff", strlen( $start ) ) === $last ) {
				break;
			}
			$start = self::step( $last, 1 );
		}
		return $out;
	}

	/**
	 * Number of trailing zero bits (capped at the address width).
	 *
	 * @param string $bin  Address.
	 * @param int    $bits Address width.
	 */
	private static function trailing_zeros( string $bin, int $bits ): int {
		$count = 0;
		for ( $i = strlen( $bin ) - 1; $i >= 0; $i-- ) {
			$byte = ord( $bin[ $i ] );
			if ( 0 === $byte ) {
				$count += 8;
				continue;
			}
			while ( 0 === ( $byte & 1 ) ) {
				++$count;
				$byte >>= 1;
			}
			return $count;
		}
		return $bits;
	}

	/**
	 * The address with its lowest $host bits set to 1.
	 *
	 * @param string $bin  Address.
	 * @param int    $host Bits to set.
	 */
	private static function fill( string $bin, int $host ): string {
		for ( $i = strlen( $bin ) - 1; $i >= 0 && $host > 0; $i-- ) {
			$take      = min( 8, $host );
			$bin[ $i ] = chr( ord( $bin[ $i ] ) | ( ( 1 << $take ) - 1 ) );
			$host     -= $take;
		}
		return $bin;
	}

	/**
	 * The address plus or minus one (callers never step past the ends).
	 *
	 * @param string $bin   Address.
	 * @param int    $delta 1 or -1.
	 */
	private static function step( string $bin, int $delta ): string {
		for ( $i = strlen( $bin ) - 1; $i >= 0; $i-- ) {
			$byte = ord( $bin[ $i ] ) + $delta;
			if ( $byte >= 0 && $byte <= 255 ) {
				$bin[ $i ] = chr( $byte );
				return $bin;
			}
			$bin[ $i ] = chr( $delta > 0 ? 0 : 255 );
		}
		return $bin;
	}
}
