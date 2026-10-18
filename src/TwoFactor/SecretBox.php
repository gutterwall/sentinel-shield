<?php
/**
 * Encrypts authenticator secrets at rest.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\TwoFactor;

defined( 'ABSPATH' ) || exit;

/**
 * XSalsa20-Poly1305 (sodium secretbox) with a key derived from the AUTH_KEY and
 * AUTH_SALT in wp-config.php, so a copy of the database alone does not reveal
 * authenticator secrets. Changing those salts makes stored secrets unreadable:
 * affected users then sign in with a backup or email code and set up their app
 * again.
 */
final class SecretBox {

	private const PREFIX = 'sb1:';

	/**
	 * Constructor.
	 *
	 * @param string $key_material Secret key material (e.g. wp_salt( 'auth' )).
	 */
	public function __construct( private string $key_material ) {}

	/**
	 * Encrypts text.
	 *
	 * @param string $plain Plain text.
	 */
	public function seal( string $plain ): string {
		$nonce = random_bytes( SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
		return self::PREFIX . base64_encode( $nonce . sodium_crypto_secretbox( $plain, $nonce, $this->key() ) ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- Binary ciphertext storage.
	}

	/**
	 * Decrypts text; null when it was sealed with another key or is damaged.
	 *
	 * @param string $sealed Sealed text.
	 */
	public function open( string $sealed ): ?string {
		if ( ! str_starts_with( $sealed, self::PREFIX ) ) {
			return null;
		}
		$raw = base64_decode( substr( $sealed, strlen( self::PREFIX ) ), true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- Binary ciphertext storage.
		if ( false === $raw || strlen( $raw ) <= SODIUM_CRYPTO_SECRETBOX_NONCEBYTES + SODIUM_CRYPTO_SECRETBOX_MACBYTES ) {
			return null;
		}
		$plain = sodium_crypto_secretbox_open( substr( $raw, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES ), substr( $raw, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES ), $this->key() );
		return false === $plain ? null : $plain;
	}

	/**
	 * Keyed hash for values that are only compared (backup and email codes).
	 */
	public function hash_key(): string {
		return hash_hmac( 'sha256', 'sentinel-shield-2fa-hash', $this->key_material );
	}

	/**
	 * The encryption key.
	 */
	private function key(): string {
		return hash_hmac( 'sha256', 'sentinel-shield-2fa-secretbox', $this->key_material, true );
	}
}
