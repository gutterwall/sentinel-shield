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
		$stored['count'] = $auth->count + 1;
		$this->assertStringContainsString( 'cloned', (string) self::assert_with( $stored, $auth->sign( $challenge ), $challenge ), 'the same counter again' );
		$stored['count'] = $auth->count;
		$this->assertSame( $auth->count + 1, self::assert_with( $stored, $auth->sign( $challenge ), $challenge ), 'one more is fine' );

		// No user presence (nobody touched the key).
		$auth->up = false;
		$this->assertStringContainsString( 'not present', (string) self::assert_with( $stored, $auth->sign( $challenge ), $challenge ) );
	}

	/**
	 * Review 5: user verification is checked whenever it is required. A key
	 * that only checks presence passes when verification is preferred and is
	 * refused, at registration and at sign-in, when it is required.
	 */
	public function test_user_verification_policy(): void {
		$touch     = new SoftAuthenticator( WebAuthn::ALG_ES256, self::RP, self::ORIGIN );
		$touch->uv = false;
		$challenge = WebAuthn::challenge();
		$response  = $touch->register( $challenge );
		$stored    = self::rp()->verify_registration( WebAuthn::unb64u( $response['client'] ), WebAuthn::unb64u( $response['attestation'] ), $challenge );
		$this->assertFalse( $stored['uv'], 'registered without user verification' );
		try {
			self::rp()->verify_registration( WebAuthn::unb64u( $response['client'] ), WebAuthn::unb64u( $response['attestation'] ), $challenge, WebAuthn::UV_REQUIRED );
			$this->fail( 'a key that did not verify the user was registered under the required policy' );
		} catch ( \RuntimeException $e ) {
			$this->assertStringContainsString( 'did not verify the user', $e->getMessage() );
		}

		$sign = static function ( SoftAuthenticator $key, array $stored, string $uv ): int|string {
			$challenge = WebAuthn::challenge();
			$response  = $key->sign( $challenge );
			try {
				return self::rp()->verify_assertion( $stored, WebAuthn::unb64u( $response['client'] ), WebAuthn::unb64u( $response['auth'] ), WebAuthn::unb64u( $response['signature'] ), $challenge, $uv );
			} catch ( \RuntimeException $e ) {
				return $e->getMessage();
			}
		};
		$this->assertIsInt( $sign( $touch, $stored, WebAuthn::UV_PREFERRED ), 'presence is enough when verification is only preferred' );
		$this->assertStringContainsString( 'did not verify the user', (string) $sign( $touch, $stored, WebAuthn::UV_REQUIRED ) );
		$this->assertStringContainsString( 'did not verify the user', (string) $sign( $touch, $stored, 'required' ) );
		$this->assertIsInt( $sign( $touch, $stored, 'anything else' ), 'unknown policies mean preferred' );

		[ $verified, $vstored ] = self::registered( WebAuthn::ALG_EDDSA );
		$this->assertIsInt( $sign( $verified, $vstored, WebAuthn::UV_REQUIRED ) );
		$this->assertIsInt( $sign( $verified, $vstored, WebAuthn::UV_PREFERRED ) );

		// The browser is asked for what the server will check.
		$user = self::factory()->user->create_and_get();
		$this->assertSame( 'required', self::rp()->request_options( $challenge, array(), WebAuthn::UV_REQUIRED )['userVerification'] );
		$this->assertSame( 'preferred', self::rp()->request_options( $challenge, array() )['userVerification'] );
		$this->assertSame( 'required', self::rp()->creation_options( $user, 'h', $challenge, array(), WebAuthn::UV_REQUIRED )['authenticatorSelection']['userVerification'] );
		$this->assertSame( 'preferred', self::rp()->creation_options( $user, 'h', $challenge, array() )['authenticatorSelection']['userVerification'] );
	}

	/**
	 * Review 5: without PHP's OpenSSL extension, passkeys degrade with a
	 * clear message instead of a fatal error: only Ed25519 keys are offered
	 * and accepted, and other signatures simply do not verify.
	 */
	public function test_without_openssl_only_ed25519_is_offered_and_nothing_crashes(): void {
		$es       = new SoftAuthenticator( WebAuthn::ALG_ES256, self::RP, self::ORIGIN );
		$ed       = new SoftAuthenticator( WebAuthn::ALG_EDDSA, self::RP, self::ORIGIN );
		$reg      = WebAuthn::challenge();
		$cases    = array(
			'es256'   => $es->register( $reg ),
			'ed25519' => $ed->register( $reg ),
		);
		$input = get_temp_dir() . 'ss-noopenssl-' . wp_generate_password( 6, false ) . '.json';
		file_put_contents( $input, (string) wp_json_encode( array( 'challenge' => $reg, 'cases' => $cases ) ) );
		$script = <<<'PHP'
<?php
define( 'ABSPATH', sys_get_temp_dir() . '/' );
require $argv[1] . '/vendor/autoload.php';
// As WordPress does (wp-includes/compat.php) on a PHP without the sodium extension.
if ( ! function_exists( 'sodium_crypto_box' ) ) {
	require $argv[3] . 'wp-includes/sodium_compat/autoload.php';
}
use SentinelShield\TwoFactor\WebAuthn;
$in  = json_decode( file_get_contents( $argv[2] ), true );
$rp  = new WebAuthn( 'shop.example.test', array( 'https://shop.example.test' ), 'Shop' );
$out = array( 'openssl' => WebAuthn::openssl(), 'algorithms' => WebAuthn::algorithms(), 'verify' => WebAuthn::verify_signature( WebAuthn::ALG_ES256, "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n", 'data', 'sig' ) );
foreach ( $in['cases'] as $name => $case ) {
	try {
		$rp->verify_registration( WebAuthn::unb64u( $case['client'] ), WebAuthn::unb64u( $case['attestation'] ), $in['challenge'] );
		$out[ $name ] = 'registered';
	} catch ( RuntimeException $e ) {
		$out[ $name ] = $e->getMessage();
	}
}
echo json_encode( $out );
PHP;
		$file = get_temp_dir() . 'ss-noopenssl-' . wp_generate_password( 6, false ) . '.php';
		file_put_contents( $file, $script );
		try {
			$cmd = sprintf( '%s -d disable_functions=openssl_verify,openssl_pkey_get_public %s %s %s %s 2>&1', escapeshellarg( PHP_BINARY ), escapeshellarg( $file ), escapeshellarg( dirname( __DIR__, 2 ) ), escapeshellarg( $input ), escapeshellarg( ABSPATH ) );
			exec( $cmd, $lines, $code );
		} finally {
			wp_delete_file( $file );
			wp_delete_file( $input );
		}
		$this->assertSame( 0, $code, implode( "\n", $lines ) );
		$out = json_decode( implode( '', $lines ), true );
		$this->assertFalse( $out['openssl'] );
		$this->assertSame( array( WebAuthn::ALG_EDDSA ), $out['algorithms'], 'only Ed25519 is offered' );
		$this->assertFalse( $out['verify'], 'an ES256 signature does not verify, without a fatal error' );
		$this->assertSame( 'registered', $out['ed25519'] );
		$this->assertStringContainsString( 'OpenSSL', $out['es256'] );
		$this->assertSame( array( WebAuthn::ALG_ES256, WebAuthn::ALG_EDDSA, WebAuthn::ALG_RS256 ), WebAuthn::algorithms(), 'with OpenSSL: all three' );
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
