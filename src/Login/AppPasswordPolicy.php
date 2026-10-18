<?php
/**
 * Application password controls.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Login;

use SentinelShield\Lockdown\AdminRegistry;
use SentinelShield\Settings;

defined( 'ABSPATH' ) || exit;

/**
 * Application passwords skip two-factor authentication by design (they are for
 * programs), so a forgotten one on an administrator account is a standing way
 * in. This limits who may use them and retires old or unused ones: they stop
 * working (WordPress keeps them listed, so the owner can see and delete them).
 */
final class AppPasswordPolicy {

	public const ERROR_EXPIRED = 'sentinel_shield_app_password_expired';
	public const ERROR_UNUSED  = 'sentinel_shield_app_password_unused';

	/**
	 * Constructor.
	 *
	 * @param Settings $settings Settings.
	 */
	public function __construct( private Settings $settings ) {}

	/**
	 * Hooks the policy.
	 */
	public function register(): void {
		add_filter( 'wp_is_application_passwords_available_for_user', array( $this, 'available_for_user' ), 10, 2 );
		add_action( 'wp_authenticate_application_password_errors', array( $this, 'check_age' ), 10, 3 );
	}

	/**
	 * Who may use application passwords at all.
	 *
	 * @param bool          $available Whether WordPress allows them.
	 * @param \WP_User|null $user      Account.
	 */
	public function available_for_user( $available, $user ): bool {
		$mode = (string) $this->settings->get( 'login.app_passwords', 'all' );
		if ( 'off' === $mode ) {
			return false;
		}
		if ( 'non_privileged' === $mode && $user instanceof \WP_User && AdminRegistry::is_privileged( $user ) ) {
			return false;
		}
		return (bool) $available;
	}

	/**
	 * Refuses application passwords past the maximum age or unused too long.
	 *
	 * @param \WP_Error            $error Errors so far.
	 * @param \WP_User             $user  Account.
	 * @param array<string, mixed> $item  The matched application password.
	 */
	public function check_age( $error, $user, $item = array() ): void {
		if ( ! $error instanceof \WP_Error || ! is_array( $item ) ) {
			return;
		}
		$status = self::status( $item, $this->settings );
		if ( 'expired' === $status ) {
			$error->add( self::ERROR_EXPIRED, __( 'This application password has expired. Create a new one under Users → Profile.', 'sentinel-shield' ), array( 'status' => 401 ) );
		} elseif ( 'unused' === $status ) {
			$error->add( self::ERROR_UNUSED, __( 'This application password was not used for too long and has been retired. Create a new one under Users → Profile.', 'sentinel-shield' ), array( 'status' => 401 ) );
		}
	}

	/**
	 * State of one application password under the policy: ok, expired or unused.
	 *
	 * @param array<string, mixed> $item     Application password (WordPress's record).
	 * @param Settings             $settings Settings.
	 * @param int|null             $now      Unix time.
	 */
	public static function status( array $item, Settings $settings, ?int $now = null ): string {
		$now     = $now ?? time();
		$created = (int) ( $item['created'] ?? 0 );
		$max     = (int) $settings->get( 'login.app_password_max_days', 0 );
		if ( $max > 0 && $created > 0 && $created < $now - $max * DAY_IN_SECONDS ) {
			return 'expired';
		}
		$unused = (int) $settings->get( 'login.app_password_unused_days', 0 );
		$last   = (int) ( $item['last_used'] ?? 0 );
		if ( $unused > 0 && max( $last, $created ) > 0 && max( $last, $created ) < $now - $unused * DAY_IN_SECONDS ) {
			return 'unused';
		}
		return 'ok';
	}
}
