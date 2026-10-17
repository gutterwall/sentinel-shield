<?php
/**
 * CIDR range value object.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Net;

defined( 'ABSPATH' ) || exit;

/**
 * An inclusive [start, end] binary range parsed from "ip" or "ip/prefix".
 */
final class Cidr {

	/**
	 * Constructor.
	 *
	 * @param string $start   Packed first address.
	 * @param string $end     Packed last address.
	 * @param int    $prefix  Prefix length.
	 * @param int    $version 4 or 6.
	 */
	private function __construct(
		public readonly string $start,
		public readonly string $end,
		public readonly int $prefix,
		public readonly int $version
	) {}

	/**
	 * Parses "192.0.2.1", "192.0.2.0/24", "2001:db8::/32" or "::ffff:10.0.0.0/104".
	 * Host bits are masked, so "192.0.2.77/24" becomes 192.0.2.0/24.
	 *
	 * @param string $input Text to parse.
	 */
	public static function parse( string $input ): ?self {
		$input = trim( $input );
		if ( '' === $input ) {
			return null;
		}
		$bits = null;
		$addr = $input;
		if ( str_contains( $input, '/' ) ) {
			[ $addr, $bits_text ] = explode( '/', $input, 2 );
			if ( '' === $bits_text || ! ctype_digit( $bits_text ) || strlen( $bits_text ) > 3 ) {
				return null;
			}
			$bits = (int) $bits_text;
		}
		$bin = IpAddress::to_binary( $addr );
		if ( null === $bin ) {
			return null;
		}
		$len = strlen( $bin ) * 8;
		// An IPv4-mapped IPv6 network: shift the prefix into IPv4 space.
		if ( null !== $bits && 32 === $len && str_contains( $addr, ':' ) ) {
			if ( $bits < 96 ) {
				return null;
			}
			$bits -= 96;
		}
		if ( null === $bits ) {
			$bits = $len;
		}
		if ( $bits < 0 || $bits > $len ) {
			return null;
		}
		$mask = self::mask( strlen( $bin ), $bits );
		return new self( $bin & $mask, $bin | ~$mask, $bits, 32 === $len ? 4 : 6 );
	}

	/**
	 * Builds the network mask for a given byte length and prefix.
	 *
	 * @param int $bytes 4 or 16.
	 * @param int $bits  Prefix length.
	 */
	private static function mask( int $bytes, int $bits ): string {
		$mask = '';
		for ( $i = 0; $i < $bytes; $i++ ) {
			$b     = max( 0, min( 8, $bits - ( 8 * $i ) ) );
			$mask .= chr( 0 === $b ? 0 : ( 0xFF << ( 8 - $b ) ) & 0xFF );
		}
		return $mask;
	}

	/**
	 * Whether the packed address falls inside this range.
	 *
	 * @param string $bin Packed address.
	 */
	public function contains( string $bin ): bool {
		return strlen( $bin ) === strlen( $this->start )
			&& strcmp( $bin, $this->start ) >= 0
			&& strcmp( $bin, $this->end ) <= 0;
	}

	/**
	 * True when the range is a single host.
	 */
	public function is_single(): bool {
		return ( 4 === $this->version ? 32 : 128 ) === $this->prefix;
	}

	/**
	 * Canonical text: "192.0.2.1" for a host, "192.0.2.0/24" for a network.
	 */
	public function to_string(): string {
		$ip = (string) IpAddress::from_binary( $this->start );
		return $this->is_single() ? $ip : $ip . '/' . $this->prefix;
	}
}
