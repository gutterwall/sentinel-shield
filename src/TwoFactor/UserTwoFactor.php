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
	public const KEYS = array( 'totp', 'totp_pending', 'totp_last_step', 'totp_added', 'email', 'backup', 'backup_created', 'devices', 'trusted', 'login', 'budget', 'passkeys', 'webauthn_handle', 'passkey_reg', 'reauth', 'reauth_challenge', 'reauth_fails' );

	public const REAUTH_TTL = 600;

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
		// A new or replaced authenticator starts with no trusted browsers.
		$this->forget_devices( $user_id );
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
		$this->forget_devices( $user_id );
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
			$this->forget_devices( $user_id );
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
		delete_user_meta( $user_id, self::META . 'trusted' );
	}

	/**
	 * Trusted browsers that have not expired: id => {created, expires, used, agent, ip}.
	 *
	 * @param int      $user_id User.
	 * @param int|null $now     Unix time.
	 * @return array<string, array{created:int, expires:int, used:int, agent:string, ip:string}>
	 */
	public function devices( int $user_id, ?int $now = null ): array {
		$now     = $now ?? time();
		$devices = get_user_meta( $user_id, self::META . 'trusted', true );
		if ( ! is_array( $devices ) ) {
			return array();
		}
		return array_filter( $devices, static fn( $d ): bool => is_array( $d ) && (int) ( $d['expires'] ?? 0 ) > $now );
	}

	/**
	 * Registers a trusted browser and returns its ID.
	 *
	 * @param int    $user_id User.
	 * @param int    $expires Unix time.
	 * @param string $agent   Browser (user agent).
	 * @param string $ip      IP it was trusted from.
	 * @param int    $now     Unix time.
	 */
	public function add_device( int $user_id, int $expires, string $agent, string $ip, int $now ): string {
		$id             = bin2hex( random_bytes( 12 ) );
		$devices        = $this->devices( $user_id, $now );
		$devices[ $id ] = array(
			'created' => $now,
			'expires' => $expires,
			'used'    => $now,
			'agent'   => mb_substr( $agent, 0, 200 ),
			'ip'      => $ip,
		);
		// Keep the 20 most recent.
		uasort( $devices, static fn( array $a, array $b ): int => $b['created'] <=> $a['created'] );
		update_user_meta( $user_id, self::META . 'trusted', array_slice( $devices, 0, 20, true ) );
		return $id;
	}

	/**
	 * Notes that a trusted browser was used (at most hourly writes).
	 *
	 * @param int    $user_id User.
	 * @param string $id   Device ID.
	 * @param int    $now  Unix time.
	 */
	public function touch_device( int $user_id, string $id, int $now ): void {
		$devices = $this->devices( $user_id, $now );
		if ( isset( $devices[ $id ] ) && $now - (int) $devices[ $id ]['used'] > HOUR_IN_SECONDS ) {
			$devices[ $id ]['used'] = $now;
			update_user_meta( $user_id, self::META . 'trusted', $devices );
		}
	}

	/**
	 * Revokes one trusted browser.
	 *
	 * @param int    $user_id User.
	 * @param string $id      Device ID.
	 */
	public function forget_device( int $user_id, string $id ): bool {
		$devices = $this->devices( $user_id );
		if ( ! isset( $devices[ $id ] ) ) {
			return false;
		}
		unset( $devices[ $id ] );
		update_user_meta( $user_id, self::META . 'trusted', $devices );
		return true;
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
	 * Registered passkeys and security keys: credential ID (base64url) => {name, alg, key, count, created, used, aaguid}.
	 *
	 * @param int $user_id User.
	 * @return array<string, array<string, mixed>>
	 */
	public function passkeys( int $user_id ): array {
		$keys = get_user_meta( $user_id, self::META . 'passkeys', true );
		return is_array( $keys ) ? $keys : array();
	}

	/**
	 * Stores a newly registered key. A new method ends trust in browsers, like
	 * any other change of methods.
	 *
	 * @param int                  $user_id User.
	 * @param array<string, mixed> $cred    WebAuthn::verify_registration() result.
	 * @param string               $name    Name the user gave it.
	 * @param int                  $now     Unix time.
	 */
	public function add_passkey( int $user_id, array $cred, string $name, int $now ): void {
		$keys                         = $this->passkeys( $user_id );
		$keys[ (string) $cred['id'] ] = array(
			'name'    => '' === trim( $name ) ? __( 'Passkey', 'sentinel-shield' ) : mb_substr( trim( $name ), 0, 60 ),
			'alg'     => (int) $cred['alg'],
			'key'     => (string) $cred['key'],
			'count'   => (int) $cred['count'],
			'created' => $now,
			'used'    => 0,
			'aaguid'  => (string) ( $cred['aaguid'] ?? '' ),
		);
		update_user_meta( $user_id, self::META . 'passkeys', $keys );
		$this->forget_devices( $user_id );
	}

	/**
	 * Removes a key.
	 *
	 * @param int    $user_id User.
	 * @param string $id      Credential ID.
	 */
	public function remove_passkey( int $user_id, string $id ): bool {
		$keys = $this->passkeys( $user_id );
		if ( ! isset( $keys[ $id ] ) ) {
			return false;
		}
		unset( $keys[ $id ] );
		$keys ? update_user_meta( $user_id, self::META . 'passkeys', $keys ) : delete_user_meta( $user_id, self::META . 'passkeys' );
		$this->forget_devices( $user_id );
		return true;
	}

	/**
	 * Records a successful use: the new signature counter and the time.
	 *
	 * @param int    $user_id User.
	 * @param string $id      Credential ID.
	 * @param int    $count   Signature counter.
	 * @param int    $now     Unix time.
	 */
	public function touch_passkey( int $user_id, string $id, int $count, int $now ): void {
		$keys = $this->passkeys( $user_id );
		if ( isset( $keys[ $id ] ) ) {
			$keys[ $id ]['count'] = $count;
			$keys[ $id ]['used']  = $now;
			update_user_meta( $user_id, self::META . 'passkeys', $keys );
		}
	}

	/**
	 * The account's WebAuthn user handle (random, not the user ID; base64url).
	 *
	 * @param int $user_id User.
	 */
	public function webauthn_handle( int $user_id ): string {
		$handle = (string) get_user_meta( $user_id, self::META . 'webauthn_handle', true );
		if ( '' === $handle ) {
			$handle = WebAuthn::b64u( random_bytes( 32 ) );
			update_user_meta( $user_id, self::META . 'webauthn_handle', $handle );
		}
		return $handle;
	}

	/**
	 * Whether the user confirmed their password (or a passkey) in this login
	 * session within the last REAUTH_TTL seconds.
	 *
	 * @param int    $user_id User.
	 * @param string $session Session token (wp_get_session_token()).
	 * @param int    $now     Unix time.
	 */
	public function recently_confirmed( int $user_id, string $session, int $now ): bool {
		if ( '' === $session ) {
			return false;
		}
		$stamps = get_user_meta( $user_id, self::META . 'reauth', true );
		return is_array( $stamps ) && (int) ( $stamps[ hash( 'sha256', $session ) ] ?? 0 ) > $now - self::REAUTH_TTL;
	}

	/**
	 * Records a fresh confirmation for this login session.
	 *
	 * @param int    $user_id User.
	 * @param string $session Session token.
	 * @param int    $now     Unix time.
	 */
	public function confirm( int $user_id, string $session, int $now ): void {
		$stamps                               = get_user_meta( $user_id, self::META . 'reauth', true );
		$stamps                               = is_array( $stamps ) ? array_filter( $stamps, static fn( $t ): bool => (int) $t > $now - self::REAUTH_TTL ) : array();
		$stamps[ hash( 'sha256', $session ) ] = $now;
		update_user_meta( $user_id, self::META . 'reauth', $stamps );
	}

	/**
	 * Summary for admin screens and WP-CLI.
	 *
	 * @param int $user_id User.
	 * @return array{totp:bool, totp_readable:bool, email:bool, backup:int, passkeys:int}
	 */
	public function summary( int $user_id ): array {
		$totp = $this->has_totp( $user_id );
		return array(
			'totp'          => $totp,
			'totp_readable' => $totp && null !== $this->totp_secret( $user_id ),
			'email'         => $this->email_enabled( $user_id ),
			'backup'        => $this->backup_remaining( $user_id ),
			'passkeys'      => count( $this->passkeys( $user_id ) ),
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
