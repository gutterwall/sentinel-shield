<?php
/**
 * Memory-compact merged range set for large lists (blocklist feeds).
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Net;

defined( 'ABSPATH' ) || exit;

/**
 * Stores sorted, non-overlapping ranges as one binary string per IP version
 * (fixed-width "start.end" records) and binary-searches it in place. Loading
 * 50,000 ranges is one base64_decode instead of unserializing 100,000 strings.
 */
final class PackedRangeSet implements RangeLookup {

	/**
	 * Record width in bytes per IP version.
	 */
	private const WIDTH = array(
		4 => 8,
		6 => 32,
	);

	/**
	 * Constructor.
	 *
	 * @param array<int, string> $packed Binary records keyed by IP version.
	 */
	private function __construct( private array $packed ) {}

	/**
	 * An empty set.
	 */
	public static function empty(): self {
		return new self(
			array(
				4 => '',
				6 => '',
			)
		);
	}

	/**
	 * Packs a merged IpRangeSet.
	 *
	 * @param IpRangeSet $set Merged set.
	 */
	public static function from_set( IpRangeSet $set ): self {
		$packed = array();
		foreach ( array( 4, 6 ) as $version ) {
			$buffer = '';
			foreach ( $set->pairs( $version ) as $pair ) {
				$buffer .= $pair[0] . $pair[1];
			}
			$packed[ $version ] = $buffer;
		}
		return new self( $packed );
	}

	/**
	 * Text-safe export for transients and the object cache.
	 *
	 * @return array<int, string>
	 */
	public function to_storage(): array {
		return array(
			4 => base64_encode( $this->packed[4] ), // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- Binary to text for storage.
			6 => base64_encode( $this->packed[6] ), // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- Binary to text for storage.
		);
	}

	/**
	 * Rebuilds from to_storage() output; anything malformed yields an empty version.
	 *
	 * @param array<mixed> $data Stored data.
	 */
	public static function from_storage( array $data ): self {
		$packed = array();
		foreach ( self::WIDTH as $version => $width ) {
			$raw                = base64_decode( (string) ( $data[ $version ] ?? '' ), true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- Text to binary from storage.
			$packed[ $version ] = ( false !== $raw && 0 === strlen( $raw ) % $width ) ? $raw : '';
		}
		return new self( $packed );
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
		$version = 4 === $len ? 4 : 6;
		$width   = self::WIDTH[ $version ];
		$data    = $this->packed[ $version ];
		$lo      = 0;
		$hi      = intdiv( strlen( $data ), $width ) - 1;
		while ( $lo <= $hi ) {
			$mid    = ( $lo + $hi ) >> 1;
			$offset = $mid * $width;
			if ( strcmp( $bin, substr( $data, $offset, $len ) ) < 0 ) {
				$hi = $mid - 1;
			} elseif ( strcmp( $bin, substr( $data, $offset + $len, $len ) ) > 0 ) {
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
		return intdiv( strlen( $this->packed[4] ), self::WIDTH[4] ) + intdiv( strlen( $this->packed[6] ), self::WIDTH[6] );
	}
}
