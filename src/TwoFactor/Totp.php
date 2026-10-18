<?php
/**
 * Time-based one-time passwords (RFC 6238) for authenticator apps.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\TwoFactor;

defined( 'ABSPATH' ) || exit;

/**
 * SHA-1, 6 digits, 30-second steps: the parameters every authenticator app
 * (Google Authenticator, Microsoft Authenticator, Authy, 1Password, Bitwarden,
 * FreeOTP) supports. Secrets are 160-bit and shown in base32 (RFC 4648).
 */
final class Totp {

	public const STEP   = 30;
	public const DIGITS = 6;

	private const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

	/**
	 * A new random secret, base32.
	 */
	public static function generate_secret(): string {
		return self::base32_encode( random_bytes( 20 ) );
	}

	/**
	 * The code for a time step.
	 *
	 * @param string $secret Base32 secret.
	 * @param int    $step   Time step (Unix time / 30).
	 */
	public static function code( string $secret, int $step ): string {
		$key  = self::base32_decode( $secret );
		$hash = hash_hmac( 'sha1', pack( 'J', $step ), $key, true );
		$off  = ord( $hash[19] ) & 0x0f;
		$bin  = ( ( ord( $hash[ $off ] ) & 0x7f ) << 24 ) | ( ord( $hash[ $off + 1 ] ) << 16 ) | ( ord( $hash[ $off + 2 ] ) << 8 ) | ord( $hash[ $off + 3 ] );
		return str_pad( (string) ( $bin % ( 10 ** self::DIGITS ) ), self::DIGITS, '0', STR_PAD_LEFT );
	}

	/**
	 * Checks a code, allowing one step of clock drift either way. A step at or
	 * before $last_step is refused, so a code cannot be used twice.
	 *
	 * @param string $secret    Base32 secret.
	 * @param string $code      Submitted code.
	 * @param int    $now       Unix time.
	 * @param int    $last_step Last step accepted for this secret (0 = none).
	 * @return int|null The matching step, or null.
	 */
	public static function verify( string $secret, string $code, int $now, int $last_step = 0 ): ?int {
		$code = preg_replace( '/\s+/', '', $code );
		if ( ! is_string( $code ) || ! preg_match( '/^\d{' . self::DIGITS . '}$/', $code ) || '' === $secret ) {
			return null;
		}
		$current = intdiv( $now, self::STEP );
		$found   = null;
		// Check every candidate so the timing does not reveal which step matched.
		foreach ( array( $current - 1, $current, $current + 1 ) as $step ) {
			if ( hash_equals( self::code( $secret, $step ), $code ) && $step > $last_step ) {
				$found = $step;
			}
		}
		return $found;
	}

	/**
	 * The otpauth:// URI that authenticator apps read from the QR code.
	 *
	 * @param string $secret  Base32 secret.
	 * @param string $account Account name shown in the app.
	 * @param string $issuer  Site name shown in the app.
	 */
	public static function uri( string $secret, string $account, string $issuer ): string {
		$issuer = str_replace( ':', '', $issuer );
		$label  = rawurlencode( $issuer ) . ':' . rawurlencode( str_replace( ':', '', $account ) );
		return 'otpauth://totp/' . $label . '?secret=' . $secret . '&issuer=' . rawurlencode( $issuer ) . '&algorithm=SHA1&digits=' . self::DIGITS . '&period=' . self::STEP;
	}

	/**
	 * Base32 encoding without padding.
	 *
	 * @param string $bytes Raw bytes.
	 */
	public static function base32_encode( string $bytes ): string {
		$out    = '';
		$buffer = 0;
		$bits   = 0;
		$length = strlen( $bytes );
		for ( $i = 0; $i < $length; $i++ ) {
			$buffer = ( ( $buffer << 8 ) | ord( $bytes[ $i ] ) ) & 0xffff;
			$bits  += 8;
			while ( $bits >= 5 ) {
				$bits -= 5;
				$out  .= self::ALPHABET[ ( $buffer >> $bits ) & 31 ];
			}
		}
		if ( $bits > 0 ) {
			$out .= self::ALPHABET[ ( $buffer << ( 5 - $bits ) ) & 31 ];
		}
		return $out;
	}

	/**
	 * Base32 decoding; ignores spaces, dashes, padding and case. Invalid
	 * characters give an empty string.
	 *
	 * @param string $text Base32 text.
	 */
	public static function base32_decode( string $text ): string {
		$text   = strtoupper( (string) preg_replace( '/[\s\-=]+/', '', $text ) );
		$out    = '';
		$buffer = 0;
		$bits   = 0;
		$length = strlen( $text );
		for ( $i = 0; $i < $length; $i++ ) {
			$value = strpos( self::ALPHABET, $text[ $i ] );
			if ( false === $value ) {
				return '';
			}
			$buffer = ( ( $buffer << 5 ) | $value ) & 0xffff;
			$bits  += 5;
			if ( $bits >= 8 ) {
				$bits -= 8;
				$out  .= chr( ( $buffer >> $bits ) & 0xff );
			}
		}
		return $out;
	}

	/**
	 * A secret split into groups of four for typing.
	 *
	 * @param string $secret Base32 secret.
	 */
	public static function format_secret( string $secret ): string {
		return trim( chunk_split( $secret, 4, ' ' ) );
	}
}
