<?php
/**
 * One-time backup codes.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\TwoFactor;

defined( 'ABSPATH' ) || exit;

/**
 * Ten codes like "k7m2-x9qp", about 41 bits each, from an alphabet without
 * look-alike characters. Only keyed hashes are stored; each code works once.
 */
final class BackupCodes {

	public const COUNT = 10;

	private const ALPHABET = 'abcdefghjkmnpqrstuvwxyz23456789';

	/**
	 * New random codes.
	 *
	 * @param int $count How many.
	 * @return list<string>
	 */
	public static function generate( int $count = self::COUNT ): array {
		$codes = array();
		$max   = strlen( self::ALPHABET ) - 1;
		while ( count( $codes ) < $count ) {
			$code = '';
			for ( $i = 0; $i < 8; $i++ ) {
				$code .= self::ALPHABET[ random_int( 0, $max ) ];
			}
			$codes[ $code ] = substr( $code, 0, 4 ) . '-' . substr( $code, 4 );
		}
		return array_values( $codes );
	}

	/**
	 * Normalizes typed input: case, spaces and dashes do not matter.
	 *
	 * @param string $code Typed code.
	 */
	public static function normalize( string $code ): string {
		return strtolower( (string) preg_replace( '/[\s\-]+/', '', $code ) );
	}

	/**
	 * Whether the input looks like a backup code.
	 *
	 * @param string $code Typed code.
	 */
	public static function looks_valid( string $code ): bool {
		return 1 === preg_match( '/^[' . self::ALPHABET . ']{8}$/', self::normalize( $code ) );
	}

	/**
	 * Keyed hash of a code.
	 *
	 * @param string $code Code (any formatting).
	 * @param string $key  Hash key.
	 */
	public static function hash( string $code, string $key ): string {
		return hash_hmac( 'sha256', self::normalize( $code ), $key );
	}
}
