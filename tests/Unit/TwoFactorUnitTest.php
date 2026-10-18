<?php
/**
 * Two-factor building blocks: TOTP, base32, QR codes, backup codes, encryption.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SentinelShield\TwoFactor\BackupCodes;
use SentinelShield\TwoFactor\QrCode;
use SentinelShield\TwoFactor\SecretBox;
use SentinelShield\TwoFactor\Totp;

final class TwoFactorUnitTest extends TestCase {

	/**
	 * RFC 6238 appendix B (SHA-1), last six digits.
	 */
	public function test_totp_matches_rfc_6238_vectors(): void {
		$secret = Totp::base32_encode( '12345678901234567890' );
		$this->assertSame( 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', $secret );
		$vectors = array(
			59          => '287082',
			1111111109  => '081804',
			1111111111  => '050471',
			1234567890  => '005924',
			2000000000  => '279037',
			20000000000 => '353130',
		);
		foreach ( $vectors as $time => $code ) {
			$this->assertSame( $code, Totp::code( $secret, intdiv( $time, 30 ) ), "time $time" );
		}
	}

	public function test_base32_round_trip_and_tolerant_decoding(): void {
		$this->assertSame( '', Totp::base32_encode( '' ) );
		for ( $len = 1; $len <= 25; $len++ ) {
			$bytes = random_bytes( $len );
			$this->assertSame( $bytes, Totp::base32_decode( Totp::base32_encode( $bytes ) ) );
		}
		$this->assertSame( 'foobar', Totp::base32_decode( 'mzxw 6ytb-oi======' ) );
		$this->assertSame( '', Totp::base32_decode( 'MZXW1' ), 'invalid character' );
		$this->assertSame( 32, strlen( Totp::generate_secret() ) );
		$this->assertSame( 'ABCD EFGH IJ', Totp::format_secret( 'ABCDEFGHIJ' ) );
	}

	public function test_verify_allows_one_step_of_drift_and_refuses_reuse(): void {
		$secret = Totp::generate_secret();
		$now    = 1700000015;
		$step   = intdiv( $now, 30 );
		$this->assertSame( $step, Totp::verify( $secret, Totp::code( $secret, $step ), $now ) );
		$this->assertSame( $step - 1, Totp::verify( $secret, Totp::code( $secret, $step - 1 ), $now ) );
		$this->assertSame( $step + 1, Totp::verify( $secret, Totp::code( $secret, $step + 1 ), $now ) );
		$this->assertNull( Totp::verify( $secret, Totp::code( $secret, $step - 2 ), $now ), 'too old' );
		$this->assertNull( Totp::verify( $secret, Totp::code( $secret, $step + 2 ), $now ), 'too far ahead' );
		$this->assertNull( Totp::verify( $secret, Totp::code( $secret, $step ), $now, $step ), 'already used' );
		$this->assertNull( Totp::verify( $secret, Totp::code( $secret, $step - 1 ), $now, $step ), 'older than the last used' );
		$code = Totp::code( $secret, $step );
		$this->assertSame( $step, Totp::verify( $secret, substr( $code, 0, 3 ) . ' ' . substr( $code, 3 ), $now ), 'space allowed' );
		$this->assertNull( Totp::verify( $secret, 'abcdef', $now ) );
		$this->assertNull( Totp::verify( $secret, '12345', $now ) );
		$this->assertNull( Totp::verify( '', '123456', $now ) );
	}

	public function test_otpauth_uri(): void {
		$uri = Totp::uri( 'ABC', 'jane@example.com', 'My: Site' );
		$this->assertSame( 'otpauth://totp/My%20Site:jane%40example.com?secret=ABC&issuer=My%20Site&algorithm=SHA1&digits=6&period=30', $uri );
	}

	/**
	 * Structure checks; decoding with a real scanner (zxing) is part of the release testing.
	 */
	public function test_qr_matrix_structure(): void {
		$cases = array(
			'a'                     => 21,
			str_repeat( 'x', 14 )   => 21,
			str_repeat( 'x', 15 )   => 25,
			str_repeat( 'x', 106 )  => 41,
			str_repeat( 'x', 107 )  => 45,
			str_repeat( 'x', 666 )  => 97,
		);
		foreach ( $cases as $text => $size ) {
			$m = QrCode::matrix( (string) $text );
			$this->assertCount( $size, $m, 'length ' . strlen( (string) $text ) );
			foreach ( array( array( 0, 0 ), array( $size - 7, 0 ), array( 0, $size - 7 ) ) as [ $ox, $oy ] ) {
				// Finder pattern: dark ring, light ring, dark 3x3 centre.
				for ( $i = 0; $i < 7; $i++ ) {
					$this->assertTrue( $m[ $oy ][ $ox + $i ] );
					$this->assertTrue( $m[ $oy + 6 ][ $ox + $i ] );
				}
				$this->assertFalse( $m[ $oy + 1 ][ $ox + 1 ] );
				$this->assertTrue( $m[ $oy + 3 ][ $ox + 3 ] );
			}
			for ( $i = 8; $i < $size - 8; $i++ ) {
				$this->assertSame( 0 === $i % 2, $m[6][ $i ], 'timing row' );
				$this->assertSame( 0 === $i % 2, $m[ $i ][6], 'timing column' );
			}
			$this->assertTrue( $m[ $size - 8 ][8], 'dark module' );
		}
		$this->expectException( \LengthException::class );
		QrCode::matrix( str_repeat( 'x', 667 ) );
	}

	public function test_qr_svg_escapes_label(): void {
		$svg = QrCode::svg( 'otpauth://totp/x', 3, '<b>"x"' );
		$this->assertStringStartsWith( '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 33 33" width="99"', $svg );
		$this->assertStringContainsString( 'aria-label="&lt;b&gt;&quot;x&quot;"', $svg );
	}

	public function test_backup_codes(): void {
		$codes = BackupCodes::generate();
		$this->assertCount( 10, $codes );
		$this->assertCount( 10, array_unique( $codes ) );
		foreach ( $codes as $code ) {
			$this->assertMatchesRegularExpression( '/^[a-z2-9]{4}-[a-z2-9]{4}$/', $code );
			$this->assertTrue( BackupCodes::looks_valid( $code ) );
			$this->assertTrue( BackupCodes::looks_valid( strtoupper( str_replace( '-', ' ', $code ) ) ) );
		}
		$this->assertFalse( BackupCodes::looks_valid( '12345678' ), '1 is not in the alphabet' );
		$this->assertFalse( BackupCodes::looks_valid( 'abcd-efg' ) );
		$this->assertSame( BackupCodes::hash( 'abcd-efgh', 'k' ), BackupCodes::hash( 'ABCD EFGH', 'k' ) );
		$this->assertNotSame( BackupCodes::hash( 'abcd-efgh', 'k' ), BackupCodes::hash( 'abcd-efgh', 'other key' ) );
	}

	public function test_secret_box(): void {
		$calls = 0;
		$box   = new SecretBox(
			static function () use ( &$calls ): string {
				++$calls;
				return 'key material';
			}
		);
		$this->assertSame( 0, $calls, 'key is read lazily' );
		$sealed = $box->seal( 'JBSWY3DPEHPK3PXP' );
		$this->assertStringStartsWith( 'sb1:', $sealed );
		$this->assertStringNotContainsString( 'JBSWY3DPEHPK3PXP', $sealed );
		$this->assertNotSame( $sealed, $box->seal( 'JBSWY3DPEHPK3PXP' ), 'random nonce' );
		$this->assertSame( 'JBSWY3DPEHPK3PXP', $box->open( $sealed ) );
		$this->assertSame( 1, $calls );

		$other = new SecretBox( static fn(): string => 'changed salts' );
		$this->assertNull( $other->open( $sealed ), 'another key cannot open it' );
		$this->assertNull( $box->open( 'JBSWY3DPEHPK3PXP' ), 'plain text is not accepted' );
		$this->assertNull( $box->open( 'sb1:' . base64_encode( 'short' ) ) );
		// Flip one ciphertext byte (editing a base64 character can land on unused padding bits).
		$raw      = base64_decode( substr( $sealed, 4 ) );
		$raw[30]  = chr( ord( $raw[30] ) ^ 1 );
		$tampered = 'sb1:' . base64_encode( $raw );
		$this->assertNull( $box->open( $tampered ) );
		$this->assertNotSame( $box->hash_key(), $other->hash_key() );
	}
}
