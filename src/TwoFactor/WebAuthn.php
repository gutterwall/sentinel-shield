<?php
/**
 * WebAuthn (passkeys and security keys): ceremony options and verification.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\TwoFactor;

defined( 'ABSPATH' ) || exit;

/**
 * Implements what a relying party must check (W3C WebAuthn Level 2, §7):
 * the client data (type, challenge, origin), the authenticator data (relying
 * party ID hash, user presence, signature counter) and the signature, with
 * ES256 (P-256), RS256 and EdDSA (Ed25519) keys. Attestation is not requested
 * ("none"): the key is trusted because a logged-in, freshly re-authenticated
 * user registered it, not because of who made the authenticator.
 */
final class WebAuthn {

	public const ALG_ES256 = -7;
	public const ALG_EDDSA = -8;
	public const ALG_RS256 = -257;

	private const FLAG_UP = 0x01;
	private const FLAG_UV = 0x04;
	private const FLAG_AT = 0x40;

	/**
	 * Constructor.
	 *
	 * @param string       $rp_id   Relying party ID (the site's host name).
	 * @param list<string> $origins Accepted origins, e.g. https://example.com.
	 * @param string       $rp_name Name shown by the browser.
	 */
	public function __construct( private string $rp_id, private array $origins, private string $rp_name = '' ) {}

	/**
	 * The relying party for this site: the login page's host, and the origins
	 * of the login page and the home page.
	 */
	public static function for_site(): self {
		$origins = array();
		foreach ( array( site_url( '/' ), home_url( '/' ), network_site_url( '/' ) ) as $url ) {
			$origin = self::origin_of( $url );
			if ( '' !== $origin ) {
				$origins[ $origin ] = true;
			}
		}
		return new self( (string) wp_parse_url( site_url( '/' ), PHP_URL_HOST ), array_keys( $origins ), wp_specialchars_decode( (string) get_bloginfo( 'name' ), ENT_QUOTES ) );
	}

	/**
	 * Scheme, host and non-default port of a URL.
	 *
	 * @param string $url URL.
	 */
	public static function origin_of( string $url ): string {
		$parts = wp_parse_url( $url );
		if ( empty( $parts['scheme'] ) || empty( $parts['host'] ) ) {
			return '';
		}
		$port = isset( $parts['port'] ) ? ':' . (int) $parts['port'] : '';
		return strtolower( $parts['scheme'] . '://' . $parts['host'] ) . $port;
	}

	/**
	 * Relying party ID.
	 */
	public function rp_id(): string {
		return $this->rp_id;
	}

	/**
	 * A new random challenge (base64url).
	 */
	public static function challenge(): string {
		return self::b64u( random_bytes( 32 ) );
	}

	/**
	 * Options for navigator.credentials.create() (binary values as base64url).
	 *
	 * @param \WP_User     $user      Account.
	 * @param string       $handle    The account's WebAuthn user handle (base64url).
	 * @param string       $challenge Challenge (base64url).
	 * @param list<string> $exclude   IDs of keys already registered (base64url).
	 * @return array<string, mixed>
	 */
	public function creation_options( \WP_User $user, string $handle, string $challenge, array $exclude ): array {
		return array(
			'rp'                     => array(
				'id'   => $this->rp_id,
				'name' => '' === $this->rp_name ? $this->rp_id : $this->rp_name,
			),
			'user'                   => array(
				'id'          => $handle,
				'name'        => $user->user_login,
				'displayName' => '' === (string) $user->display_name ? $user->user_login : (string) $user->display_name,
			),
			'challenge'              => $challenge,
			'pubKeyCredParams'       => array(
				array(
					'type' => 'public-key',
					'alg'  => self::ALG_ES256,
				),
				array(
					'type' => 'public-key',
					'alg'  => self::ALG_EDDSA,
				),
				array(
					'type' => 'public-key',
					'alg'  => self::ALG_RS256,
				),
			),
			'timeout'                => 120000,
			'attestation'            => 'none',
			'excludeCredentials'     => array_map(
				static fn( string $id ): array => array(
					'type' => 'public-key',
					'id'   => $id,
				),
				$exclude
			),
			'authenticatorSelection' => array(
				'residentKey'      => 'preferred',
				'userVerification' => 'preferred',
			),
		);
	}

	/**
	 * Options for navigator.credentials.get().
	 *
	 * @param string       $challenge Challenge (base64url).
	 * @param list<string> $allow     IDs of the account's keys (base64url).
	 * @return array<string, mixed>
	 */
	public function request_options( string $challenge, array $allow ): array {
		return array(
			'challenge'        => $challenge,
			'rpId'             => $this->rp_id,
			'timeout'          => 120000,
			'userVerification' => 'preferred',
			'allowCredentials' => array_map(
				static fn( string $id ): array => array(
					'type' => 'public-key',
					'id'   => $id,
				),
				$allow
			),
		);
	}

	/**
	 * Verifies a registration response.
	 *
	 * @param string $client_json       clientDataJSON (raw bytes).
	 * @param string $attestation       attestationObject (raw bytes).
	 * @param string $expect_challenge  The challenge that was issued (base64url).
	 * @return array{id:string, alg:int, key:string, count:int, aaguid:string, uv:bool}
	 * @throws \RuntimeException When anything does not check out.
	 */
	public function verify_registration( string $client_json, string $attestation, string $expect_challenge ): array {
		$this->check_client( $client_json, 'webauthn.create', $expect_challenge );
		try {
			$object = Cbor::decode( $attestation );
		} catch ( \InvalidArgumentException $e ) {
			throw new \RuntimeException( 'The attestation object is not valid CBOR.' );
		}
		if ( ! is_array( $object ) || ! isset( $object['authData'] ) || ! is_string( $object['authData'] ) ) {
			throw new \RuntimeException( 'The attestation object has no authenticator data.' );
		}
		$auth = $this->parse_auth_data( $object['authData'] );
		if ( ! ( $auth['flags'] & self::FLAG_AT ) || ! isset( $auth['credential'] ) ) {
			throw new \RuntimeException( 'No credential was created.' );
		}
		$cred = $auth['credential'];
		return array(
			'id'     => self::b64u( $cred['id'] ),
			'alg'    => $cred['alg'],
			'key'    => $cred['key'],
			'count'  => $auth['count'],
			'aaguid' => bin2hex( $cred['aaguid'] ),
			'uv'     => (bool) ( $auth['flags'] & self::FLAG_UV ),
		);
	}

	/**
	 * Verifies an authentication response.
	 *
	 * @param array{alg:int, key:string, count:int} $stored          The registered key.
	 * @param string                                $client_json     clientDataJSON (raw bytes).
	 * @param string                                $auth_data       authenticatorData (raw bytes).
	 * @param string                                $signature       Signature (raw bytes).
	 * @param string                                $expect_challenge The challenge that was issued (base64url).
	 * @return int The new signature counter.
	 * @throws \RuntimeException When anything does not check out.
	 */
	public function verify_assertion( array $stored, string $client_json, string $auth_data, string $signature, string $expect_challenge ): int {
		$this->check_client( $client_json, 'webauthn.get', $expect_challenge );
		$auth = $this->parse_auth_data( $auth_data );
		if ( ! self::verify_signature( (int) $stored['alg'], (string) $stored['key'], $auth_data . hash( 'sha256', $client_json, true ), $signature ) ) {
			throw new \RuntimeException( 'The signature is not valid.' );
		}
		// A counter that does not increase means a cloned authenticator (when it counts at all).
		if ( ( $auth['count'] > 0 || (int) $stored['count'] > 0 ) && $auth['count'] <= (int) $stored['count'] ) {
			throw new \RuntimeException( 'The authenticator\'s counter went backwards; it may have been cloned.' );
		}
		return $auth['count'];
	}

	/**
	 * Checks clientDataJSON.
	 *
	 * @param string $client_json Raw JSON.
	 * @param string $type        Expected type.
	 * @param string $challenge   Expected challenge (base64url).
	 * @throws \RuntimeException On mismatch.
	 */
	private function check_client( string $client_json, string $type, string $challenge ): void {
		$client = json_decode( $client_json, true );
		if ( ! is_array( $client ) ) {
			throw new \RuntimeException( 'The client data is not valid JSON.' );
		}
		if ( ( $client['type'] ?? '' ) !== $type ) {
			throw new \RuntimeException( 'Wrong ceremony type.' );
		}
		if ( '' === $challenge || ! hash_equals( $challenge, (string) ( $client['challenge'] ?? '' ) ) ) {
			throw new \RuntimeException( 'The challenge does not match (expired or reused).' );
		}
		if ( ! in_array( strtolower( (string) ( $client['origin'] ?? '' ) ), $this->origins, true ) ) {
			throw new \RuntimeException( 'The request came from another site.' );
		}
		if ( ! empty( $client['crossOrigin'] ) ) {
			throw new \RuntimeException( 'Cross-origin requests are not accepted.' );
		}
	}

	/**
	 * Parses authenticator data.
	 *
	 * @param string $data Raw bytes.
	 * @return array{flags:int, count:int, credential?:array{aaguid:string, id:string, alg:int, key:string}}
	 * @throws \RuntimeException When malformed or for another site.
	 */
	private function parse_auth_data( string $data ): array {
		if ( strlen( $data ) < 37 ) {
			throw new \RuntimeException( 'The authenticator data is too short.' );
		}
		if ( ! hash_equals( hash( 'sha256', $this->rp_id, true ), substr( $data, 0, 32 ) ) ) {
			throw new \RuntimeException( 'The key belongs to another site.' );
		}
		$flags = ord( $data[32] );
		if ( ! ( $flags & self::FLAG_UP ) ) {
			throw new \RuntimeException( 'The user was not present.' );
		}
		$out = array(
			'flags' => $flags,
			'count' => (int) unpack( 'N', substr( $data, 33, 4 ) )[1],
		);
		if ( $flags & self::FLAG_AT ) {
			if ( strlen( $data ) < 55 ) {
				throw new \RuntimeException( 'The credential data is too short.' );
			}
			$aaguid = substr( $data, 37, 16 );
			$len    = (int) unpack( 'n', substr( $data, 53, 2 ) )[1];
			$id     = substr( $data, 55, $len );
			if ( strlen( $id ) !== $len || $len < 16 || $len > 1023 ) {
				throw new \RuntimeException( 'The credential ID is not valid.' );
			}
			try {
				$cose = Cbor::decode( substr( $data, 55 + $len ) );
			} catch ( \InvalidArgumentException $e ) {
				throw new \RuntimeException( 'The public key is not valid CBOR.' );
			}
			$key               = self::cose_key( is_array( $cose ) ? $cose : array() );
			$out['credential'] = array(
				'aaguid' => $aaguid,
				'id'     => $id,
				'alg'    => $key['alg'],
				'key'    => $key['key'],
			);
		}
		return $out;
	}

	/**
	 * Converts a COSE public key to what the verifier needs: a PEM public key
	 * (ES256, RS256) or the raw 32-byte key (EdDSA).
	 *
	 * @param array<int|string, mixed> $cose COSE_Key map.
	 * @return array{alg:int, key:string}
	 * @throws \RuntimeException For unsupported keys.
	 */
	public static function cose_key( array $cose ): array {
		$kty = $cose[1] ?? null;
		$alg = $cose[3] ?? null;
		if ( 2 === $kty && self::ALG_ES256 === $alg && 1 === ( $cose[-1] ?? null ) ) {
			$x = (string) ( $cose[-2] ?? '' );
			$y = (string) ( $cose[-3] ?? '' );
			if ( 32 !== strlen( $x ) || 32 !== strlen( $y ) ) {
				throw new \RuntimeException( 'The P-256 key is malformed.' );
			}
			$der = hex2bin( '3059301306072a8648ce3d020106082a8648ce3d030107034200' ) . "\x04" . $x . $y;
			return array(
				'alg' => self::ALG_ES256,
				'key' => self::pem( $der ),
			);
		}
		if ( 3 === $kty && self::ALG_RS256 === $alg ) {
			$n = ltrim( (string) ( $cose[-1] ?? '' ), "\0" );
			$e = ltrim( (string) ( $cose[-2] ?? '' ), "\0" );
			if ( strlen( $n ) < 256 || '' === $e ) {
				throw new \RuntimeException( 'The RSA key is malformed or shorter than 2048 bits.' );
			}
			$rsa = self::der( 0x30, self::der_int( $n ) . self::der_int( $e ) );
			$der = self::der( 0x30, self::der( 0x30, hex2bin( '06092a864886f70d0101010500' ) ) . self::der( 0x03, "\0" . $rsa ) );
			return array(
				'alg' => self::ALG_RS256,
				'key' => self::pem( $der ),
			);
		}
		if ( 1 === $kty && self::ALG_EDDSA === $alg && 6 === ( $cose[-1] ?? null ) ) {
			$x = (string) ( $cose[-2] ?? '' );
			if ( 32 !== strlen( $x ) ) {
				throw new \RuntimeException( 'The Ed25519 key is malformed.' );
			}
			return array(
				'alg' => self::ALG_EDDSA,
				'key' => $x,
			);
		}
		throw new \RuntimeException( 'This kind of key is not supported (use ES256, RS256 or EdDSA).' );
	}

	/**
	 * Checks a signature.
	 *
	 * @param int    $alg       COSE algorithm.
	 * @param string $key       PEM or raw Ed25519 key.
	 * @param string $data      Signed data.
	 * @param string $signature Signature.
	 */
	public static function verify_signature( int $alg, string $key, string $data, string $signature ): bool {
		if ( self::ALG_EDDSA === $alg ) {
			return 64 === strlen( $signature ) && 32 === strlen( $key ) && sodium_crypto_sign_verify_detached( $signature, $data, $key );
		}
		if ( self::ALG_ES256 === $alg || self::ALG_RS256 === $alg ) {
			$public = openssl_pkey_get_public( $key );
			return false !== $public && 1 === openssl_verify( $data, $signature, $public, OPENSSL_ALGO_SHA256 );
		}
		return false;
	}

	/**
	 * Base64url without padding.
	 *
	 * @param string $bytes Raw bytes.
	 */
	public static function b64u( string $bytes ): string {
		return rtrim( strtr( base64_encode( $bytes ), '+/', '-_' ), '=' ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- WebAuthn's binary encoding.
	}

	/**
	 * Decodes base64url (padding optional). Returns '' when invalid.
	 *
	 * @param string $text Text.
	 */
	public static function unb64u( string $text ): string {
		if ( ! preg_match( '/^[A-Za-z0-9_-]*={0,2}$/', $text ) ) {
			return '';
		}
		return (string) base64_decode( strtr( rtrim( $text, '=' ), '-_', '+/' ), true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- WebAuthn's binary encoding.
	}

	/**
	 * DER element.
	 *
	 * @param int    $tag     Tag byte.
	 * @param string $content Content.
	 */
	private static function der( int $tag, string $content ): string {
		$len = strlen( $content );
		if ( $len < 128 ) {
			return chr( $tag ) . chr( $len ) . $content;
		}
		$bytes = ltrim( pack( 'N', $len ), "\0" );
		return chr( $tag ) . chr( 0x80 | strlen( $bytes ) ) . $bytes . $content;
	}

	/**
	 * DER INTEGER from unsigned big-endian bytes.
	 *
	 * @param string $bytes Bytes.
	 */
	private static function der_int( string $bytes ): string {
		if ( ord( $bytes[0] ) & 0x80 ) {
			$bytes = "\0" . $bytes;
		}
		return self::der( 0x02, $bytes );
	}

	/**
	 * PEM-encodes a SubjectPublicKeyInfo.
	 *
	 * @param string $der DER bytes.
	 */
	private static function pem( string $der ): string {
		return "-----BEGIN PUBLIC KEY-----\n" . chunk_split( base64_encode( $der ), 64, "\n" ) . "-----END PUBLIC KEY-----\n"; // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- PEM encoding.
	}
}
