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
use SentinelShield\Repository\LoginAttemptRepository;
use SentinelShield\Repository\OffenseRepository;
use SentinelShield\Repository\TokenRepository;
use SentinelShield\Settings;
use SentinelShield\Firewall\EarlyGate;
use SentinelShield\Audit\AuditExporter;

defined( 'ABSPATH' ) || exit;

/**
 * Hourly pruning and weekly Cloudflare range refresh. Runs on the main site only,
 * because the tables are network-wide.
 */
final class MaintenanceModule implements ModuleInterface {

	public const CRON_HOOKS = array( 'sentinel_shield_maintenance', 'sentinel_shield_cf_refresh' );
	public const LAST_RUN   = 'sentinel_shield_maintenance_last';
	public const REPORT     = 'sentinel_shield_maintenance_report';

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
	 * @param Container  $container Services.
	 * @param float|null $budget    Seconds (default: the setting). Every
	 *                              table still gets at least one batch.
	 * @return array<string, int> Rows removed per table.
	 */
	public static function run( Container $container, ?float $budget = null ): array {
		$settings = $container->get( Settings::class );
		$audit    = $container->get( AuditExporter::class );
		$events   = $container->get( EventRepository::class );
		$logins   = $container->get( LoginAttemptRepository::class );
		// One time budget for the whole run (storage budgets: review 5).
		$until = microtime( true ) + ( $budget ?? max( 5, (int) $settings->get( 'general.maintenance_seconds', 20 ) ) );
		$left  = static fn(): float => max( 0.0, $until - microtime( true ) );
		// Events not yet delivered to the remote audit log are kept, within their own limits.
		$audit->note_dropped();
		$window = (int) $settings->get( 'login.window_minutes', 15 ) * MINUTE_IN_SECONDS;
		$keep   = $audit->retention_cursor();
		$result = array(
			'rules'    => $container->get( BlockRepository::class )->purge_expired(),
			'events'   => $events->prune( (int) $settings->get( 'general.event_retention_days', 30 ), $keep, $audit->unsent_days(), $left() )
				+ $events->trim( (int) $settings->get( 'general.event_max_rows', 250000 ), $keep, $audit->unsent_rows(), $left() ),
			'offenses' => $container->get( OffenseRepository::class )->prune( time() - $settings->lockout_window() ),
			'tokens'   => $container->get( TokenRepository::class )->prune(),
			// The detailed history for the Login Security overview; the limits use the
			// counters, which are kept for the counting window whatever the history setting.
			'logins'   => $logins->prune( time() - max( (int) $settings->get( 'login.history_days', 7 ) * DAY_IN_SECONDS, $window ), $left() )
				+ $logins->trim( (int) $settings->get( 'login.history_max_rows', 500000 ), time() - $window, $left() ),
		);
		if ( $result['rules'] > 0 ) {
			$container->get( RuleCache::class )->flush();
		}
		$gate            = $container->get( EarlyGate::class );
		$result['early'] = $gate->import_log();
		EarlyGate::maybe_clean_legacy();
		$gate->rebuild_if_dirty();
		$audit->heartbeat();
		$audit->run( min( 15.0, max( 1.0, $left() ) ) );
		// Out of time with work left: continue soon rather than in an hour.
		$result['unfinished'] = 0 === (int) ceil( $left() ) ? 1 : 0;
		if ( $result['unfinished'] && ! wp_next_scheduled( 'sentinel_shield_maintenance', array( 'more' ) ) ) {
			wp_schedule_single_event( time() + 5 * MINUTE_IN_SECONDS, 'sentinel_shield_maintenance', array( 'more' ) );
		}
		update_site_option( self::LAST_RUN, time() );
		update_site_option( self::REPORT, $result + array( 'time' => time() ) );
		return $result;
	}
}
