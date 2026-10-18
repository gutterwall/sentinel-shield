<?php
/**
 * Activation and deactivation.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Install;

use SentinelShield\Cron\CronControl;
use SentinelShield\Feeds\FeedUpdater;
use SentinelShield\Geo\GeoUpdater;
use SentinelShield\Firewall\RuleCache;
use SentinelShield\Lockdown\UploadGuard;
use SentinelShield\Modules\LockdownModule;
use SentinelShield\Modules\MaintenanceModule;
use SentinelShield\Net\Cidr;
use SentinelShield\Net\ClientIpFactory;
use SentinelShield\Plugin;
use SentinelShield\Repository\BlockRepository;
use SentinelShield\Safety\AdminProtection;
use SentinelShield\Safety\SafetyGuard;
use SentinelShield\Settings;
use SentinelShield\Support\Secret;
use SentinelShield\Firewall\EarlyGate;
use SentinelShield\Firewall\CloudflareSync;
use SentinelShield\Audit\AuditExporter;

defined( 'ABSPATH' ) || exit;

/**
 * Activation creates tables, stores defaults (test mode on) and allowlists the activating admin.
 */
final class Installer {

	/**
	 * Activation hook.
	 *
	 * @param bool $network_wide Network activation flag (unused: tables are always network-wide).
	 */
	public static function activate( bool $network_wide = false ): void {
		unset( $network_wide );
		Schema::install();
		Secret::get();

		if ( false === get_site_option( Settings::OPTION, false ) ) {
			update_site_option( Settings::OPTION, Settings::defaults() );
			update_site_option( 'sentinel_shield_welcome', 1 );
		}

		$container = Plugin::instance()->container();
		$container->get( Settings::class )->refresh();
		// Restore the uploads rules that deactivation removed.
		LockdownModule::on_settings_saved( $container );
		if ( $container->get( SafetyGuard::class )->is_cli() ) {
			// WP-CLI fakes REMOTE_ADDR as 127.0.0.1; allowlisting it could exempt all proxied traffic.
			if ( class_exists( '\WP_CLI' ) ) {
				\WP_CLI::log( 'Sentinel Shield: activated from WP-CLI, so no IP was allowlisted. Your IP is allowlisted the first time you save Sentinel Shield settings in wp-admin.' );
			}
			return;
		}
		$details = $container->get( ClientIpFactory::class )->from_globals()->details();
		$ip      = (string) $details['ip'];
		// Loopback/proxy addresses stand for every visitor behind a not-yet-configured proxy.
		$cidr = AdminProtection::is_real_client( $details ) ? Cidr::parse( $ip ) : null;
		if ( null !== $cidr ) {
			$days = (int) $container->get( Settings::class )->get( 'unlock.admin_allow_days', 30 );
			$container->get( BlockRepository::class )->add(
				'allow',
				$cidr,
				__( 'Administrator IP at plugin activation', 'sentinel-shield' ),
				'admin_auto',
				$days > 0 ? time() + $days * DAY_IN_SECONDS : null,
				get_current_user_id()
			);
			$container->get( RuleCache::class )->flush();
		}
	}

	/**
	 * Deactivation hook: unschedule our cron events and resume paused ones. Data is kept.
	 */
	public static function deactivate(): void {
		// Without the plugin nothing keeps paused tasks paused, so put them back rather than lose one-off tasks.
		foreach ( array_keys( CronControl::paused() ) as $key ) {
			CronControl::resume( $key );
		}
		// Without the plugin the rules would be unmanaged; reactivating re-adds them on the next settings save.
		UploadGuard::sync_htaccess( false );
		// Without the plugin the early firewall would run on a stale snapshot.
		EarlyGate::remove_loader();
		wp_clear_scheduled_hook( CloudflareSync::CRON );
		wp_clear_scheduled_hook( AuditExporter::CRON );
		foreach ( array_merge( MaintenanceModule::CRON_HOOKS, LockdownModule::CRON_HOOKS, array( FeedUpdater::CRON_HOOK, GeoUpdater::CRON_HOOK ) ) as $hook ) {
			wp_clear_scheduled_hook( $hook );
			wp_clear_scheduled_hook( $hook, array( 'soon' ) );
		}
	}
}
