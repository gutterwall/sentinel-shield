<?php
/**
 * IP address helpers (binary conversion and normalization).
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Net;

defined( 'ABSPATH' ) || exit;

/**
 * Converts between text and packed binary IP representations.
 *
 * IPv4 addresses are always 4 bytes and IPv6 addresses 16 bytes. IPv4-mapped
 * IPv6 addresses (::ffff:192.0.2.1) collapse to their 4-byte IPv4 form so the
 * same client never has two identities.
 */
final class IpAddress {

	/**
	 * Returns true when the input is a valid IPv4 or IPv6 address.
	 *
	 * @param string $ip Candidate address.
	 */
	public static function is_valid( string $ip ): bool {
		return null !== self::to_binary( $ip );
	}

	/**
	 * Packs an address into 4 or 16 bytes, or returns null when invalid.
	 *
	 * @param string $ip Address text. Brackets, ports and zone IDs are tolerated.
	 */
	public static function to_binary( string $ip ): ?string {
		$ip = self::clean( $ip );
		if ( '' === $ip || false === filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return null;
		}
		$bin = inet_pton( $ip );
		if ( false === $bin ) {
			return null;
		}
		if ( 16 === strlen( $bin ) && str_repeat( "\0", 10 ) . "\xff\xff" === substr( $bin, 0, 12 ) ) {
			return substr( $bin, 12 );
		}
		return $bin;
	}

	/**
	 * Unpacks a 4 or 16 byte binary address to canonical text.
	 *
	 * @param string $bin Packed address.
	 */
	public static function from_binary( string $bin ): ?string {
		$len = strlen( $bin );
		if ( 4 !== $len && 16 !== $len ) {
			return null;
		}
		$text = inet_ntop( $bin );
		return false === $text ? null : $text;
	}

	/**
	 * Returns the canonical text form (e.g. compressed, lowercase IPv6) or null.
	 *
	 * @param string $ip Address text.
	 */
	public static function normalize( string $ip ): ?string {
		$bin = self::to_binary( $ip );
		return null === $bin ? null : self::from_binary( $bin );
	}

	/**
	 * IP version (4 or 6) of a packed address.
	 *
	 * @param string $bin Packed address.
	 */
	public static function version( string $bin ): int {
		return 4 === strlen( $bin ) ? 4 : 6;
	}

	/**
	 * Whether a packed address is loopback, link-local, private (RFC 1918 / ULA) or CGNAT.
	 *
	 * @param string $bin Packed address.
	 */
	public static function is_private( string $bin ): bool {
		static $set = null;
		if ( null === $set ) {
			$set = IpRangeSet::from_strings(
				array( '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8', '100.64.0.0/10', '169.254.0.0/16', '::1/128', 'fc00::/7', 'fe80::/10' )
			);
		}
		return $set->contains( $bin );
	}

	/**
	 * Strips whitespace, brackets, ports and IPv6 zone identifiers.
	 *
	 * @param string $ip Raw input.
	 */
	private static function clean( string $ip ): string {
		$ip = trim( $ip );
		if ( preg_match( '/^\[([0-9a-zA-Z:.%]+)\](?::\d{1,5})?$/', $ip, $m ) ) {
			$ip = $m[1];
		} elseif ( preg_match( '/^(\d{1,3}(?:\.\d{1,3}){3}):\d{1,5}$/', $ip, $m ) ) {
			$ip = $m[1];
		}
		$zone = strpos( $ip, '%' );
		if ( false !== $zone ) {
			$ip = substr( $ip, 0, $zone );
		}
		return $ip;
	}
}
