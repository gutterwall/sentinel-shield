<?php
/**
 * Test helper: a software WebAuthn authenticator plus browser.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Tests\Integration;

use SentinelShield\TwoFactor\WebAuthn;

/**
 * Creates keys (ES256, EdDSA or RS256), registration responses with "none"
 * attestation and signed assertions, exactly as a browser would send them.
 */
final class SoftAuthenticator {

	public string $id;

	public int $count = 0;

	/**
	 * Whether it verifies the user (fingerprint, face or PIN) or only checks
	 * presence, like a security key without a PIN.
	 */
	public bool $uv = true;

	/**
	 * Whether it reports user presence (the UP flag); off only to test refusal.
	 */
	public bool $up = true;

	/**
	 * Private key (OpenSSL) or Ed25519 secret key.
	 *
	 * @var mixed
	 */
	private mixed $private;

	/**
	 * COSE public key map.
	 *
	 * @var array<int, mixed>
	 */
	private array $cose;

	/**
	 * Constructor.
	 *
	 * @param int    $alg    COSE algorithm.
	 * @param string $rp_id  Relying party ID.
	 * @param string $origin Origin the "browser" reports.
	 */
	public function __construct( public int $alg, private string $rp_id, public string $origin ) {
		$this->id = random_bytes( 32 );
		if ( WebAuthn::ALG_EDDSA === $alg ) {
			$pair          = sodium_crypto_sign_keypair();
			$this->private = sodium_crypto_sign_secretkey( $pair );
			$this->cose    = array(
				1  => 1,
				3  => WebAuthn::ALG_EDDSA,
				-1 => 6,
				-2 => sodium_crypto_sign_publickey( $pair ),
			);
		} elseif ( WebAuthn::ALG_RS256 === $alg ) {
			$this->private = openssl_pkey_new(
				array(
					'private_key_type' => OPENSSL_KEYTYPE_RSA,
					'private_key_bits' => 2048,
				)
			);
			$rsa           = openssl_pkey_get_details( $this->private )['rsa'];
			$this->cose    = array(
				1  => 3,
				3  => WebAuthn::ALG_RS256,
				-1 => $rsa['n'],
				-2 => $rsa['e'],
			);
		} else {
			$this->private = openssl_pkey_new(
				array(
					'private_key_type' => OPENSSL_KEYTYPE_EC,
					'curve_name'       => 'prime256v1',
				)
			);
			$ec            = openssl_pkey_get_details( $this->private )['ec'];
			$this->cose    = array(
				1  => 2,
				3  => WebAuthn::ALG_ES256,
				-1 => 1,
				-2 => str_pad( $ec['x'], 32, "\0", STR_PAD_LEFT ),
				-3 => str_pad( $ec['y'], 32, "\0", STR_PAD_LEFT ),
			);
		}
	}

	/**
	 * A registration response: [clientDataJSON, attestationObject] as base64url.
	 *
	 * @param string $challenge Challenge (base64url).
	 * @param string $type      Ceremony type to claim.
	 * @return array{client:string, attestation:string}
	 */
	public function register( string $challenge, string $type = 'webauthn.create' ): array {
		$client = (string) wp_json_encode(
			array(
				'type'      => $type,
				'challenge' => $challenge,
				'origin'    => $this->origin,
			)
		);
		$auth   = hash( 'sha256', $this->rp_id, true ) . chr( 0x40 | ( $this->up ? 0x01 : 0 ) | ( $this->uv ? 0x04 : 0 ) ) . pack( 'N', $this->count ) . str_repeat( "\0", 16 ) . pack( 'n', strlen( $this->id ) ) . $this->id . self::cbor( $this->cose );
		return array(
			'client'      => WebAuthn::b64u( $client ),
			'attestation' => WebAuthn::b64u(
				self::cbor(
					array(
						'fmt'      => 'none',
						'attStmt'  => array(),
						'authData' => new CborBytes( $auth ),
					)
				)
			),
		);
	}

	/**
	 * An authentication response, as base64url fields.
	 *
	 * @param string $challenge Challenge (base64url).
	 * @param int    $bump      How much the counter goes up.
	 * @return array{id:string, client:string, auth:string, signature:string}
	 */
	public function sign( string $challenge, int $bump = 1 ): array {
		$this->count += $bump;
		$client       = (string) wp_json_encode(
			array(
				'type'      => 'webauthn.get',
				'challenge' => $challenge,
				'origin'    => $this->origin,
			)
		);
		$auth         = hash( 'sha256', $this->rp_id, true ) . chr( ( $this->up ? 0x01 : 0 ) | ( $this->uv ? 0x04 : 0 ) ) . pack( 'N', $this->count );
		$data         = $auth . hash( 'sha256', $client, true );
		if ( WebAuthn::ALG_EDDSA === $this->alg ) {
			$signature = sodium_crypto_sign_detached( $data, $this->private );
		} else {
			openssl_sign( $data, $signature, $this->private, OPENSSL_ALGO_SHA256 );
		}
		return array(
			'id'        => WebAuthn::b64u( $this->id ),
			'client'    => WebAuthn::b64u( $client ),
			'auth'      => WebAuthn::b64u( $auth ),
			'signature' => WebAuthn::b64u( (string) $signature ),
		);
	}

	/**
	 * Minimal CBOR encoder (ints, strings, byte strings, maps, lists).
	 *
	 * @param mixed $value Value.
	 */
	public static function cbor( mixed $value ): string {
		if ( $value instanceof CborBytes ) {
			return self::head( 2, strlen( $value->bytes ) ) . $value->bytes;
		}
		if ( is_int( $value ) ) {
			return $value >= 0 ? self::head( 0, $value ) : self::head( 1, -1 - $value );
		}
		if ( is_string( $value ) ) {
			// Text for ASCII words (map keys like "fmt"), bytes otherwise.
			return preg_match( '/^[A-Za-z]+$/', $value ) ? self::head( 3, strlen( $value ) ) . $value : self::head( 2, strlen( $value ) ) . $value;
		}
		if ( is_array( $value ) ) {
			$out = self::head( 5, count( $value ) );
			foreach ( $value as $k => $v ) {
				$out .= self::cbor( $k ) . self::cbor( $v );
			}
			return $out;
		}
		throw new \InvalidArgumentException( 'Unsupported value' );
	}

	/**
	 * CBOR head.
	 *
	 * @param int $major Major type.
	 * @param int $n     Length or value.
	 */
	private static function head( int $major, int $n ): string {
		if ( $n < 24 ) {
			return chr( ( $major << 5 ) | $n );
		}
		if ( $n < 256 ) {
			return chr( ( $major << 5 ) | 24 ) . chr( $n );
		}
		if ( $n < 65536 ) {
			return chr( ( $major << 5 ) | 25 ) . pack( 'n', $n );
		}
		return chr( ( $major << 5 ) | 26 ) . pack( 'N', $n );
	}
}

/**
 * Marks a string as a CBOR byte string.
 */
final class CborBytes {

	/**
	 * Constructor.
	 *
	 * @param string $bytes Bytes.
	 */
	public function __construct( public string $bytes ) {}
}
