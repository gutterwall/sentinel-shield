<?php
/**
 * Scheduled housekeeping. Always on.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Modules;

use SentinelShield\Container;
use SentinelShield\Firewall\RuleCache;
use SentinelShield\Net\CloudflareRanges;
use SentinelShield\Repository\BlockRepository;
use SentinelShield\Repository\EventRepository;
use SentinelShield\Repository\OffenseRepository;
use SentinelShield\Repository\TokenRepository;
use SentinelShield\Settings;

defined( 'ABSPATH' ) || exit;

/**
 * Hourly pruning and weekly Cloudflare range refresh. Runs on the main site only,
 * because the tables are network-wide.
 */
final class MaintenanceModule implements ModuleInterface {

	public const CRON_HOOKS = array( 'sentinel_shield_maintenance', 'sentinel_shield_cf_refresh' );

	/**
	 * {@inheritDoc}
	 */
	public function slug(): string {
		return 'maintenance';
	}

	/**
	 * {@inheritDoc}
	 *
	 * @param Container $container Services.
	 */
	public function register( Container $container ): void {
		add_action(
			'sentinel_shield_maintenance',
			static function () use ( $container ): void {
				self::run( $container );
			}
		);
		add_action(
			'sentinel_shield_cf_refresh',
			static function () use ( $container ): void {
				if ( 'cloudflare' === $container->get( Settings::class )->get( 'proxy.mode' ) ) {
					$container->get( CloudflareRanges::class )->refresh();
				}
			}
		);
		add_action(
			'init',
			static function (): void {
				if ( ! is_main_site() ) {
					return;
				}
				if ( ! wp_next_scheduled( 'sentinel_shield_maintenance' ) ) {
					wp_schedule_event( time() + MINUTE_IN_SECONDS, 'hourly', 'sentinel_shield_maintenance' );
				}
				if ( ! wp_next_scheduled( 'sentinel_shield_cf_refresh' ) ) {
					wp_schedule_event( time() + HOUR_IN_SECONDS, 'weekly', 'sentinel_shield_cf_refresh' );
				}
			}
		);
	}

	/**
	 * Runs housekeeping now.
	 *
	 * @param Container $container Services.
	 * @return array<string, int> Rows removed per table.
	 */
	public static function run( Container $container ): array {
		$settings = $container->get( Settings::class );
		$result   = array(
			'rules'    => $container->get( BlockRepository::class )->purge_expired(),
			'events'   => $container->get( EventRepository::class )->prune( (int) $settings->get( 'general.event_retention_days', 30 ) ),
			'offenses' => $container->get( OffenseRepository::class )->prune( time() - $settings->lockout_window() ),
			'tokens'   => $container->get( TokenRepository::class )->prune(),
		);
		if ( $result['rules'] > 0 ) {
			$container->get( RuleCache::class )->flush();
		}
		return $result;
	}
}
