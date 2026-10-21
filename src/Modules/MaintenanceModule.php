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
use SentinelShield\Support\Deadline;

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
	 * Runs housekeeping now: database pruning and local files only. Network
	 * work has its own jobs (the heartbeat, audit delivery); this run only
	 * makes sure they are scheduled.
	 *
	 * The budget is a deadline every step shares: a step is started only while
	 * time is left, the database steps stop between small batches, and a
	 * policy build (which cannot stop half-way) starts only if the last one
	 * would fit, otherwise it is handed to its own background job. Steps that
	 * did not run, or stopped with work left, are reported and continued in
	 * five minutes.
	 *
	 * @param Container           $container Services.
	 * @param float|Deadline|null $budget    Seconds or a deadline (default: the setting, at least 5 s).
	 * @return array<string, mixed> Rows removed per table, unfinished (0/1), deferred steps, seconds.
	 */
	public static function run( Container $container, float|Deadline|null $budget = null ): array {
		$settings = $container->get( Settings::class );
		$audit    = $container->get( AuditExporter::class );
		$events   = $container->get( EventRepository::class );
		$logins   = $container->get( LoginAttemptRepository::class );
		$gate     = $container->get( EarlyGate::class );
		$started  = microtime( true );
		$deadline = $budget instanceof Deadline ? $budget : Deadline::in( $budget ?? max( 5, (int) $settings->get( 'general.maintenance_seconds', 20 ) ) );
		$window   = (int) $settings->get( 'login.window_minutes', 15 ) * MINUTE_IN_SECONDS;
		$steps    = array(
			'rules'    => static fn(): int => $container->get( BlockRepository::class )->purge_expired(),
			'tokens'   => static fn(): int => $container->get( TokenRepository::class )->prune(),
			'offenses' => static fn(): int => $container->get( OffenseRepository::class )->prune( time() - $settings->lockout_window() ),
			'events'   => static function () use ( $audit, $events, $settings, $deadline ): int {
				// Events not yet delivered to the remote audit log are kept, within their own limits.
				$audit->note_dropped();
				$keep = $audit->retention_cursor();
				return $events->prune( (int) $settings->get( 'general.event_retention_days', 30 ), $keep, $audit->unsent_days(), $deadline )
					+ $events->trim( (int) $settings->get( 'general.event_max_rows', 250000 ), $keep, $audit->unsent_rows(), $deadline );
			},
			// The detailed history for the Login Security overview; the limits use the
			// counters, which are kept for the counting window whatever the history setting.
			'logins'   => static fn(): int => $logins->prune( time() - max( (int) $settings->get( 'login.history_days', 7 ) * DAY_IN_SECONDS, $window ), $deadline )
				+ $logins->trim( (int) $settings->get( 'login.history_max_rows', 500000 ), time() - $window, $deadline ),
			'early'    => static fn(): int => $gate->import_log(),
			'legacy'   => static function (): int {
				EarlyGate::clean_legacy_leftovers();
				return 0;
			},
			'policy'   => static function () use ( $gate, $deadline ): int {
				$gate->rebuild_if_dirty( $deadline );
				return 0;
			},
		);
		$result   = array();
		$deferred = array();
		foreach ( $steps as $name => $step ) {
			if ( $deadline->expired() ) {
				$deadline->cut();
				$deferred[] = $name;
				continue;
			}
			$result[ $name ] = $step();
		}
		unset( $result['legacy'], $result['policy'] );
		$result += array_fill_keys( array( 'rules', 'tokens', 'offenses', 'events', 'logins', 'early' ), 0 );
		if ( $result['rules'] > 0 ) {
			$container->get( RuleCache::class )->flush();
		}
		$audit->ensure_scheduled();
		// Out of time with work left: continue soon rather than in an hour.
		$result['unfinished'] = $deadline->was_cut() ? 1 : 0;
		$result['deferred']   = $deferred;
		$result['seconds']    = round( microtime( true ) - $started, 2 );
		if ( $result['unfinished'] && ! wp_next_scheduled( 'sentinel_shield_maintenance', array( 'more' ) ) ) {
			wp_schedule_single_event( time() + 5 * MINUTE_IN_SECONDS, 'sentinel_shield_maintenance', array( 'more' ) );
		}
		update_site_option( self::LAST_RUN, time() );
		update_site_option( self::REPORT, $result + array( 'time' => time() ) );
		return $result;
	}
}
