<?php
/**
 * WebAuthn verification against a software authenticator.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Tests\Integration;

use SentinelShield\TwoFactor\Cbor;
use SentinelShield\TwoFactor\WebAuthn;

final class WebAuthnTest extends \WP_UnitTestCase {

	private const RP     = 'shop.example.test';
	private const ORIGIN = 'https://shop.example.test';

	private static function rp(): WebAuthn {
		return new WebAuthn( self::RP, array( self::ORIGIN ), 'Shop' );
	}

	/**
	 * Registers a soft authenticator and returns it with the stored key.
	 *
	 * @param int $alg COSE algorithm.
	 * @return array{0:SoftAuthenticator, 1:array<string, mixed>}
	 */
	private static function registered( int $alg ): array {
		$auth      = new SoftAuthenticator( $alg, self::RP, self::ORIGIN );
		$challenge = WebAuthn::challenge();
		$response  = $auth->register( $challenge );
		$stored    = self::rp()->verify_registration( WebAuthn::unb64u( $response['client'] ), WebAuthn::unb64u( $response['attestation'] ), $challenge );
		return array( $auth, $stored );
	}

	/**
	 * Runs an assertion; returns the new counter or the error message.
	 *
	 * @param array<string, mixed> $stored    Stored key.
	 * @param array<string, string> $response Assertion.
	 * @param string               $challenge Expected challenge.
	 */
	private static function assert_with( array $stored, array $response, string $challenge ): int|string {
		try {
			return self::rp()->verify_assertion( $stored, WebAuthn::unb64u( $response['client'] ), WebAuthn::unb64u( $response['auth'] ), WebAuthn::unb64u( $response['signature'] ), $challenge );
		} catch ( \RuntimeException $e ) {
			return $e->getMessage();
		}
	}

	/**
	 * @return array<string, array{0:int}>
	 */
	public static function algorithms(): array {
		return array(
			'ES256' => array( WebAuthn::ALG_ES256 ),
			'EdDSA' => array( WebAuthn::ALG_EDDSA ),
			'RS256' => array( WebAuthn::ALG_RS256 ),
		);
	}

	/**
	 * @dataProvider algorithms
	 */
	public function test_register_and_sign_in( int $alg ): void {
		[ $auth, $stored ] = self::registered( $alg );
		$this->assertSame( WebAuthn::b64u( $auth->id ), $stored['id'] );
		$this->assertSame( $alg, $stored['alg'] );
		$this->assertTrue( $stored['uv'] );

		$challenge = WebAuthn::challenge();
		$this->assertSame( 1, self::assert_with( $stored, $auth->sign( $challenge ), $challenge ) );
	}

	public function test_registration_is_rejected_when_anything_is_off(): void {
		$auth      = new SoftAuthenticator( WebAuthn::ALG_ES256, self::RP, self::ORIGIN );
		$challenge = WebAuthn::challenge();
		$check     = static function ( array $response, string $expect ) use ( $challenge ): string {
			try {
				self::rp()->verify_registration( WebAuthn::unb64u( $response['client'] ), WebAuthn::unb64u( $response['attestation'] ), $expect );
				return 'accepted';
			} catch ( \RuntimeException $e ) {
				return $e->getMessage();
			}
		};
		$this->assertStringContainsString( 'challenge', $check( $auth->register( $challenge ), WebAuthn::challenge() ) );
		$this->assertStringContainsString( 'ceremony', $check( $auth->register( $challenge, 'webauthn.get' ), $challenge ) );

		$evil = new SoftAuthenticator( WebAuthn::ALG_ES256, self::RP, 'https://evil.example' );
		$this->assertStringContainsString( 'another site', $check( $evil->register( $challenge ), $challenge ) );

		$other = new SoftAuthenticator( WebAuthn::ALG_ES256, 'other.example', self::ORIGIN );
		$this->assertStringContainsString( 'another site', $check( $other->register( $challenge ), $challenge ), 'key scoped to another relying party' );

		$response                = $auth->register( $challenge );
		$response['attestation'] = WebAuthn::b64u( "\xff\x00" );
		$this->assertStringContainsString( 'CBOR', $check( $response, $challenge ) );
	}

	public function test_assertions_are_rejected_when_anything_is_off(): void {
		[ $auth, $stored ] = self::registered( WebAuthn::ALG_ES256 );
		$challenge         = WebAuthn::challenge();

		$this->assertStringContainsString( 'challenge', (string) self::assert_with( $stored, $auth->sign( $challenge ), WebAuthn::challenge() ) );

		// Signed by another key.
		[ $other ]   = self::registered( WebAuthn::ALG_ES256 );
		$this->assertStringContainsString( 'signature', (string) self::assert_with( $stored, $other->sign( $challenge ), $challenge ) );

		// Tampered authenticator data (counter changed after signing).
		$response         = $auth->sign( $challenge );
		$raw              = WebAuthn::unb64u( $response['auth'] );
		$raw[36]          = chr( ord( $raw[36] ) ^ 1 );
		$response['auth'] = WebAuthn::b64u( $raw );
		$this->assertStringContainsString( 'signature', (string) self::assert_with( $stored, $response, $challenge ) );

		// A cloned authenticator: the counter does not go up.
		$stored['count'] = 50;
		$this->assertStringContainsString( 'cloned', (string) self::assert_with( $stored, $auth->sign( $challenge ), $challenge ) );
	}

	public function test_cbor_decoder_handles_and_rejects(): void {
		$this->assertSame( array( 1 => 2, -1 => 'ab', 'fmt' => 'none' ), Cbor::decode( SoftAuthenticator::cbor( array( 1 => 2, -1 => 'ab', 'fmt' => 'none' ) ) ) );
		$this->assertSame( array( true, false, null ), Cbor::decode( "\x83\xf5\xf4\xf6" ) );
		foreach ( array( "\x5f", "\xc0\x01", "\x42\x01", "\xf9\x00\x00", str_repeat( "\x81", 40 ) . "\x01" ) as $bad ) {
			try {
				Cbor::decode( $bad );
				$this->fail( 'accepted ' . bin2hex( $bad ) );
			} catch ( \InvalidArgumentException $e ) {
				$this->assertNotSame( '', $e->getMessage() );
			}
		}
	}

	public function test_short_rsa_keys_and_unknown_algorithms_are_refused(): void {
		$this->expectException( \RuntimeException::class );
		WebAuthn::cose_key(
			array(
				1  => 3,
				3  => WebAuthn::ALG_RS256,
				-1 => random_bytes( 128 ),
				-2 => "\x01\x00\x01",
			)
		);
	}
}
