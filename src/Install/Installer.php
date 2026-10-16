<?php
/**
 * Activation and deactivation.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Install;

use SentinelShield\Firewall\RuleCache;
use SentinelShield\Modules\MaintenanceModule;
use SentinelShield\Net\Cidr;
use SentinelShield\Net\ClientIpFactory;
use SentinelShield\Plugin;
use SentinelShield\Repository\BlockRepository;
use SentinelShield\Settings;
use SentinelShield\Support\Secret;

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
		$ip   = $container->get( ClientIpFactory::class )->from_globals()->resolve();
		$cidr = '' === $ip ? null : Cidr::parse( $ip );
		if ( null !== $cidr ) {
			$container->get( BlockRepository::class )->add(
				'allow',
				$cidr,
				__( 'Administrator IP at plugin activation', 'sentinel-shield' ),
				'admin_auto',
				null,
				get_current_user_id()
			);
			$container->get( RuleCache::class )->flush();
		}
	}

	/**
	 * Deactivation hook: unschedule cron events. Data is kept.
	 */
	public static function deactivate(): void {
		foreach ( MaintenanceModule::CRON_HOOKS as $hook ) {
			wp_clear_scheduled_hook( $hook );
		}
	}
}
