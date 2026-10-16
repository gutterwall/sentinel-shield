<?php
/**
 * Compiled, merged set of IP ranges with O(log n) lookups.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Net;

defined( 'ABSPATH' ) || exit;

/**
 * Overlapping ranges are merged and sorted per IP version, so membership is a
 * binary search over byte-comparable strings. This keeps the per-request block
 * check well under the 5 ms budget even with tens of thousands of entries.
 */
final class IpRangeSet {

	/**
	 * Ranges keyed by IP version.
	 *
	 * @var array<int, list<array{0:string,1:string}>>
	 */
	private array $ranges = array(
		4 => array(),
		6 => array(),
	);

	/**
	 * Use the named constructors.
	 */
	private function __construct() {}

	/**
	 * An empty set.
	 */
	public static function empty(): self {
		return new self();
	}

	/**
	 * Builds a set from IP/CIDR strings; invalid entries are ignored.
	 *
	 * @param iterable<mixed> $items Strings.
	 */
	public static function from_strings( iterable $items ): self {
		$pairs = array();
		foreach ( $items as $item ) {
			$cidr = Cidr::parse( (string) $item );
			if ( null !== $cidr ) {
				$pairs[] = array( $cidr->start, $cidr->end );
			}
		}
		return self::from_pairs( $pairs );
	}

	/**
	 * Builds a set from packed [start, end] pairs, merging overlaps.
	 *
	 * @param array<int, array{0:string,1:string}> $pairs Pairs.
	 */
	public static function from_pairs( array $pairs ): self {
		$set = new self();
		$by  = array(
			4 => array(),
			6 => array(),
		);
		foreach ( $pairs as $pair ) {
			[ $start, $end ] = $pair;
			$len             = strlen( $start );
			if ( ( 4 !== $len && 16 !== $len ) || strlen( $end ) !== $len ) {
				continue;
			}
			if ( strcmp( $start, $end ) > 0 ) {
				[ $start, $end ] = array( $end, $start );
			}
			$by[ 4 === $len ? 4 : 6 ][] = array( $start, $end );
		}
		foreach ( $by as $version => $list ) {
			usort( $list, static fn( array $a, array $b ): int => strcmp( $a[0], $b[0] ) );
			$merged = array();
			foreach ( $list as $range ) {
				$last = count( $merged ) - 1;
				if ( $last >= 0 && strcmp( $range[0], $merged[ $last ][1] ) <= 0 ) {
					if ( strcmp( $range[1], $merged[ $last ][1] ) > 0 ) {
						$merged[ $last ][1] = $range[1];
					}
				} else {
					$merged[] = $range;
				}
			}
			$set->ranges[ $version ] = $merged;
		}
		return $set;
	}

	/**
	 * Splits a textarea/CSV list into entries, dropping blanks and # comments.
	 *
	 * @param string $text Raw text.
	 * @return list<string>
	 */
	public static function parse_lines( string $text ): array {
		$out   = array();
		$lines = preg_split( '/\r\n|\r|\n|,/', $text );
		foreach ( false === $lines ? array() : $lines as $line ) {
			$hash = strpos( $line, '#' );
			if ( false !== $hash ) {
				$line = substr( $line, 0, $hash );
			}
			$line = trim( $line );
			if ( '' !== $line ) {
				$out[] = $line;
			}
		}
		return $out;
	}

	/**
	 * Binary-search membership test.
	 *
	 * @param string $bin Packed address.
	 */
	public function contains( string $bin ): bool {
		$len = strlen( $bin );
		if ( 4 !== $len && 16 !== $len ) {
			return false;
		}
		$list = $this->ranges[ 4 === $len ? 4 : 6 ];
		$lo   = 0;
		$hi   = count( $list ) - 1;
		while ( $lo <= $hi ) {
			$mid = ( $lo + $hi ) >> 1;
			if ( strcmp( $bin, $list[ $mid ][0] ) < 0 ) {
				$hi = $mid - 1;
			} elseif ( strcmp( $bin, $list[ $mid ][1] ) > 0 ) {
				$lo = $mid + 1;
			} else {
				return true;
			}
		}
		return false;
	}

	/**
	 * Number of merged ranges.
	 */
	public function count(): int {
		return count( $this->ranges[4] ) + count( $this->ranges[6] );
	}

	/**
	 * Hex-encoded export, safe for transients stored in utf8mb4 columns.
	 *
	 * @return array<int, list<array{0:string,1:string}>>
	 */
	public function to_array(): array {
		$out = array();
		foreach ( $this->ranges as $version => $list ) {
			$out[ $version ] = array_map( static fn( array $r ): array => array( bin2hex( $r[0] ), bin2hex( $r[1] ) ), $list );
		}
		return $out;
	}

	/**
	 * Rebuilds a set exported with to_array(). Malformed entries are skipped.
	 *
	 * @param array<mixed> $data Exported data.
	 */
	public static function from_array( array $data ): self {
		$set = new self();
		foreach ( array( 4, 6 ) as $version ) {
			$bytes = 4 === $version ? 4 : 16;
			foreach ( (array) ( $data[ $version ] ?? array() ) as $pair ) {
				if ( ! is_array( $pair ) || ! isset( $pair[0], $pair[1] ) ) {
					continue;
				}
				$s = (string) $pair[0];
				$e = (string) $pair[1];
				if ( strlen( $s ) !== $bytes * 2 || strlen( $e ) !== $bytes * 2 || ! ctype_xdigit( $s . $e ) ) {
					continue;
				}
				$set->ranges[ $version ][] = array( (string) hex2bin( $s ), (string) hex2bin( $e ) );
			}
		}
		return $set;
	}
}
