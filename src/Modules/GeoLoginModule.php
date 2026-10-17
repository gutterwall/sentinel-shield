<?php
/**
 * Login location (GeoIP) restriction module.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Modules;

use SentinelShield\Admin\View;
use SentinelShield\Container;
use SentinelShield\Geo\GeoUpdater;
use SentinelShield\Geo\LoginGeoGuard;
use SentinelShield\Settings;

defined( 'ABSPATH' ) || exit;

/**
 * Checks logins against the allowed or blocked countries and keeps the local
 * country database current. Saving settings that would deny the administrator
 * who saves them (even after their IP is auto-allowlisted) puts the module into
 * test mode instead of locking them out.
 */
final class GeoLoginModule implements ModuleInterface {

	/**
	 * Whether the settings-saved handler is running (it may save settings itself).
	 *
	 * @var bool
	 */
	private static bool $saving = false;

	/**
	 * {@inheritDoc}
	 */
	public function slug(): string {
		return 'geo_login';
	}

	/**
	 * {@inheritDoc}
	 *
	 * @param Container $container Services.
	 */
	public function register( Container $container ): void {
		$container->get( LoginGeoGuard::class )->register();
		add_action(
			GeoUpdater::CRON_HOOK,
			static function () use ( $container ): void {
				$container->get( GeoUpdater::class )->tick();
			}
		);
		add_action(
			'init',
			static function (): void {
				if ( is_main_site() && ! wp_next_scheduled( GeoUpdater::CRON_HOOK ) ) {
					wp_schedule_event( time() + wp_rand( 10, 120 ) * MINUTE_IN_SECONDS, 'daily', GeoUpdater::CRON_HOOK );
				}
			}
		);
	}

	/**
	 * Purges or schedules the database. Always hooked (see Plugin::boot), so it
	 * also runs when the module itself is switched on or off.
	 *
	 * @param Container $container Services.
	 */
	public static function on_settings_saved( Container $container ): void {
		if ( self::$saving ) {
			return;
		}
		self::$saving = true;
		try {
			$settings = $container->get( Settings::class );
			$settings->refresh();
			$updater = $container->get( GeoUpdater::class );
			if ( ! $settings->get( 'geo.dbip', false ) ) {
				if ( $updater->state() || is_file( GeoUpdater::path() ) ) {
					$updater->purge();
				}
			} elseif ( $updater->due() ) {
				GeoUpdater::schedule_soon( 10 );
			}
		} finally {
			self::$saving = false;
		}
	}

	/**
	 * If the logged-in user saving the settings could not log in again from here,
	 * switches the module to test mode and says so. Called by every admin save
	 * after the admin's IP has been auto-allowlisted, so it only steps in when the
	 * allowlist cannot help (e.g. the detected IP is a proxy or loopback address).
	 *
	 * @param Container $container Services.
	 */
	public static function protect_current_admin( Container $container ): void {
		$settings = $container->get( Settings::class );
		$settings->refresh();
		$user = wp_get_current_user();
		if ( ! $user->exists() || ( defined( 'WP_CLI' ) && WP_CLI ) || wp_doing_cron() || ! $settings->is_enabled() || ! $settings->is_module_enabled( 'geo_login' ) || $settings->is_test_mode( 'geo_login' ) ) {
			return;
		}
		$check = $container->get( LoginGeoGuard::class )->check( (string) $container->get( 'client_ip' ), $user, true );
		if ( $check['allowed'] ) {
			return;
		}
		$all = $settings->network_settings();
		Settings::set_path( $all, 'modules.geo_login.test_mode', 'on' );
		$settings->save_network( $all );
		View::flash(
			'warning',
			/* translators: %s: explanation. */
			sprintf( __( 'Login location: with these settings you could not log in again from where you are now (%s) Login location was put into test mode, so denied logins are only logged. Fix the country list, or add your IP to the allowlist, then set its test mode back on the Modules tab.', 'sentinel-shield' ), LoginGeoGuard::explain( $check ) )
		);
	}
}
