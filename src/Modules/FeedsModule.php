<?php
/**
 * Scheduled blocklist feed updates.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Modules;

use SentinelShield\Container;
use SentinelShield\Feeds\FeedUpdater;

defined( 'ABSPATH' ) || exit;

/**
 * An hourly tick updates whichever enabled feeds are due; each feed's own
 * interval decides how often it is actually downloaded. Matching requests
 * against downloaded feeds is done by the Gate (ip_gate module).
 */
final class FeedsModule implements ModuleInterface {

	/**
	 * {@inheritDoc}
	 */
	public function slug(): string {
		return 'feeds';
	}

	/**
	 * {@inheritDoc}
	 *
	 * @param Container $container Services.
	 */
	public function register( Container $container ): void {
		add_action(
			FeedUpdater::CRON_HOOK,
			static function () use ( $container ): void {
				$container->get( FeedUpdater::class )->tick();
			}
		);
		add_action(
			'init',
			static function (): void {
				if ( is_main_site() && ! wp_next_scheduled( FeedUpdater::CRON_HOOK ) ) {
					// Random offset so sites sharing a host do not all fetch on the hour.
					wp_schedule_event( time() + wp_rand( 5, 55 ) * MINUTE_IN_SECONDS, 'hourly', FeedUpdater::CRON_HOOK );
				}
			}
		);
		add_action(
			'sentinel_shield_settings_saved',
			static function () use ( $container ): void {
				$updater = $container->get( FeedUpdater::class );
				$updater->purge_disabled();
				if ( $updater->due() ) {
					// Newly enabled lists load within a minute instead of waiting for the hourly tick.
					FeedUpdater::schedule_soon( 10 );
				}
			}
		);
	}
}
