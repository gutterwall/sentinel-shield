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
use SentinelShield\Support\Mailer;
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
		// Without the plugin nothing would keep the other layers in step: the early
		// firewall stops (no snapshot), server files are emptied, Cloudflare is cleared.
		EarlyGate::deactivate();
		self::clear_cloudflare( Plugin::instance()->container()->get( CloudflareSync::class ) );
		wp_clear_scheduled_hook( CloudflareSync::CRON );
		wp_clear_scheduled_hook( CloudflareSync::CHECK );
		wp_clear_scheduled_hook( AuditExporter::CRON );
		foreach ( array_merge( MaintenanceModule::CRON_HOOKS, LockdownModule::CRON_HOOKS, array( FeedUpdater::CRON_HOOK, GeoUpdater::CRON_HOOK ) ) as $hook ) {
			wp_clear_scheduled_hook( $hook );
			wp_clear_scheduled_hook( $hook, array( 'soon' ) );
			wp_clear_scheduled_hook( $hook, array( 'more' ) );
		}
	}

	/**
	 * Empties the Cloudflare list on deactivation and waits briefly for
	 * Cloudflare to confirm. Nothing runs after deactivation, so when the
	 * emptying is not confirmed the site admin is emailed how to finish it.
	 *
	 * @param CloudflareSync $cloudflare Sync service.
	 */
	private static function clear_cloudflare( CloudflareSync $cloudflare ): void {
		if ( ! $cloudflare->manages_items() || $cloudflare->clear_remote( __( 'plugin deactivated', 'sentinel-shield' ), true ) ) {
			return;
		}
		$state = CloudflareSync::state();
		$lists = array( (array) ( $state['dest'] ?? array() ) );
		foreach ( (array) ( $state['retired'] ?? array() ) as $old ) {
			$lists[] = $old;
		}
		$names = array();
		foreach ( $lists as $list ) {
			if ( ! empty( $list['list'] ) ) {
				/* translators: 1: list ID, 2: account ID. */
				$names[] = sprintf( __( 'list %1$s in account %2$s', 'sentinel-shield' ), (string) $list['list'], (string) ( $list['account'] ?? '' ) );
			}
		}
		$body = sprintf(
			/* translators: 1: site address, 2: list names, 3: error. */
			__( "Sentinel Shield was deactivated on %1\$s, but Cloudflare did not confirm that its IP list was emptied (%2\$s). %3\$s\n\nThe addresses in it are still blocked at Cloudflare and nothing on the site manages them any more. To finish:\n\n1. In Cloudflare, open Manage Account > Configurations > Lists and remove the items of that list (or delete the list).\n2. Or remove or disable the WAF custom rule that uses the list (Security > WAF > Custom rules).\n3. Or reactivate Sentinel Shield, switch Cloudflare sync off on Settings > Server & CDN and wait until the list shows as emptied.", 'sentinel-shield' ),
			home_url( '/' ),
			$names ? implode( ', ', $names ) : __( 'unknown list', 'sentinel-shield' ),
			(string) ( $state['error'] ?? '' )
		);
		Mailer::send( (string) get_site_option( 'admin_email' ), __( 'Sentinel Shield: Cloudflare list not confirmed empty', 'sentinel-shield' ), $body, 'alert' );
	}
}
