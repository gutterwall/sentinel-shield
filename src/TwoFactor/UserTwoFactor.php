<?php
/**
 * Per-user two-factor settings.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\TwoFactor;

defined( 'ABSPATH' ) || exit;

/**
 * Stored in user meta (shared by every site of a network). The authenticator
 * secret is encrypted; backup codes are stored as keyed hashes.
 */
final class UserTwoFactor {

	public const META = '_sentinel_shield_2fa_';

	/**
	 * Every meta key this class and the login flow write.
	 */
	public const KEYS = array( 'totp', 'totp_pending', 'totp_last_step', 'totp_added', 'email', 'backup', 'backup_created', 'devices', 'login' );

	/**
	 * Constructor.
	 *
	 * @param SecretBox $box Encryption.
	 */
	public function __construct( private SecretBox $box ) {}

	/**
	 * Whether an authenticator app is set up (even if its secret is unreadable).
	 *
	 * @param int $user_id User.
	 */
	public function has_totp( int $user_id ): bool {
		return '' !== (string) get_user_meta( $user_id, self::META . 'totp', true );
	}

	/**
	 * The authenticator secret, or null when none is set up or it cannot be decrypted.
	 *
	 * @param int $user_id User.
	 */
	public function totp_secret( int $user_id ): ?string {
		$sealed = (string) get_user_meta( $user_id, self::META . 'totp', true );
		return '' === $sealed ? null : $this->box->open( $sealed );
	}

	/**
	 * The secret being set up, created on first call.
	 *
	 * @param int  $user_id User.
	 * @param bool $renew   Start over with a new secret.
	 */
	public function pending_secret( int $user_id, bool $renew = false ): string {
		$sealed = (string) get_user_meta( $user_id, self::META . 'totp_pending', true );
		$secret = $renew || '' === $sealed ? null : $this->box->open( $sealed );
		if ( null === $secret ) {
			$secret = Totp::generate_secret();
			update_user_meta( $user_id, self::META . 'totp_pending', $this->box->seal( $secret ) );
		}
		return $secret;
	}

	/**
	 * Activates the pending secret if the code matches it.
	 *
	 * @param int    $user_id User.
	 * @param string $code    Code from the app.
	 * @param int    $now     Unix time.
	 */
	public function enable_totp( int $user_id, string $code, int $now ): bool {
		$secret = $this->pending_secret( $user_id );
		$step   = Totp::verify( $secret, $code, $now );
		if ( null === $step ) {
			return false;
		}
		update_user_meta( $user_id, self::META . 'totp', $this->box->seal( $secret ) );
		update_user_meta( $user_id, self::META . 'totp_last_step', $step );
		update_user_meta( $user_id, self::META . 'totp_added', $now );
		delete_user_meta( $user_id, self::META . 'totp_pending' );
		return true;
	}

	/**
	 * Removes the authenticator app.
	 *
	 * @param int $user_id User.
	 */
	public function disable_totp( int $user_id ): void {
		foreach ( array( 'totp', 'totp_pending', 'totp_last_step', 'totp_added' ) as $key ) {
			delete_user_meta( $user_id, self::META . $key );
		}
	}

	/**
	 * Checks an authenticator code; each code works once.
	 *
	 * @param int    $user_id User.
	 * @param string $code    Code.
	 * @param int    $now     Unix time.
	 */
	public function verify_totp( int $user_id, string $code, int $now ): bool {
		$secret = $this->totp_secret( $user_id );
		if ( null === $secret ) {
			return false;
		}
		$step = Totp::verify( $secret, $code, $now, (int) get_user_meta( $user_id, self::META . 'totp_last_step', true ) );
		if ( null === $step ) {
			return false;
		}
		update_user_meta( $user_id, self::META . 'totp_last_step', $step );
		return true;
	}

	/**
	 * Whether the user chose email codes.
	 *
	 * @param int $user_id User.
	 */
	public function email_enabled( int $user_id ): bool {
		return '1' === (string) get_user_meta( $user_id, self::META . 'email', true );
	}

	/**
	 * Switches email codes on or off for the user.
	 *
	 * @param int  $user_id User.
	 * @param bool $on      On.
	 */
	public function set_email( int $user_id, bool $on ): void {
		if ( $on ) {
			update_user_meta( $user_id, self::META . 'email', '1' );
		} else {
			delete_user_meta( $user_id, self::META . 'email' );
		}
	}

	/**
	 * Replaces the backup codes; returns the new codes (shown once).
	 *
	 * @param int $user_id User.
	 * @return list<string>
	 */
	public function new_backup_codes( int $user_id ): array {
		$codes = BackupCodes::generate();
		$key   = $this->box->hash_key();
		update_user_meta( $user_id, self::META . 'backup', array_map( static fn( string $c ): string => BackupCodes::hash( $c, $key ), $codes ) );
		update_user_meta( $user_id, self::META . 'backup_created', time() );
		return $codes;
	}

	/**
	 * Unused backup codes left.
	 *
	 * @param int $user_id User.
	 */
	public function backup_remaining( int $user_id ): int {
		return count( $this->backup_hashes( $user_id ) );
	}

	/**
	 * Uses up a backup code if it is valid.
	 *
	 * @param int    $user_id User.
	 * @param string $code    Code.
	 */
	public function use_backup_code( int $user_id, string $code ): bool {
		if ( ! BackupCodes::looks_valid( $code ) ) {
			return false;
		}
		$hash   = BackupCodes::hash( $code, $this->box->hash_key() );
		$hashes = $this->backup_hashes( $user_id );
		$match  = null;
		foreach ( $hashes as $i => $stored ) {
			if ( hash_equals( $stored, $hash ) ) {
				$match = $i;
			}
		}
		if ( null === $match ) {
			return false;
		}
		unset( $hashes[ $match ] );
		update_user_meta( $user_id, self::META . 'backup', array_values( $hashes ) );
		return true;
	}

	/**
	 * Removes the backup codes.
	 *
	 * @param int $user_id User.
	 */
	public function delete_backup_codes( int $user_id ): void {
		delete_user_meta( $user_id, self::META . 'backup' );
		delete_user_meta( $user_id, self::META . 'backup_created' );
	}

	/**
	 * Version number that trusted-browser cookies are tied to.
	 *
	 * @param int $user_id User.
	 */
	public function device_version( int $user_id ): int {
		return (int) get_user_meta( $user_id, self::META . 'devices', true );
	}

	/**
	 * Invalidates every "trust this browser" cookie of the user.
	 *
	 * @param int $user_id User.
	 */
	public function forget_devices( int $user_id ): void {
		update_user_meta( $user_id, self::META . 'devices', $this->device_version( $user_id ) + 1 );
	}

	/**
	 * Removes every method and trusted browser (administrator reset, lost phone).
	 *
	 * @param int $user_id User.
	 */
	public function reset( int $user_id ): void {
		$this->forget_devices( $user_id );
		foreach ( self::KEYS as $key ) {
			if ( 'devices' !== $key ) {
				delete_user_meta( $user_id, self::META . $key );
			}
		}
	}

	/**
	 * Summary for admin screens and WP-CLI.
	 *
	 * @param int $user_id User.
	 * @return array{totp:bool, totp_readable:bool, email:bool, backup:int}
	 */
	public function summary( int $user_id ): array {
		$totp = $this->has_totp( $user_id );
		return array(
			'totp'          => $totp,
			'totp_readable' => $totp && null !== $this->totp_secret( $user_id ),
			'email'         => $this->email_enabled( $user_id ),
			'backup'        => $this->backup_remaining( $user_id ),
		);
	}

	/**
	 * Stored backup code hashes.
	 *
	 * @param int $user_id User.
	 * @return list<string>
	 */
	private function backup_hashes( int $user_id ): array {
		$hashes = get_user_meta( $user_id, self::META . 'backup', true );
		return is_array( $hashes ) ? array_values( array_filter( $hashes, 'is_string' ) ) : array();
	}
}
