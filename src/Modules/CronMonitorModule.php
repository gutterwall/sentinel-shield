<?php
/**
 * Records WP-Cron runs for the Scheduled Tasks page.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Modules;

use SentinelShield\Container;
use SentinelShield\Cron\CronRecorder;

defined( 'ABSPATH' ) || exit;

/**
 * Starts the recorder in cron and WP-CLI requests, after all plugins have
 * attached their callbacks and before wp-cron.php runs due events.
 */
final class CronMonitorModule implements ModuleInterface {

	/**
	 * {@inheritDoc}
	 */
	public function slug(): string {
		return 'cron_monitor';
	}

	/**
	 * {@inheritDoc}
	 *
	 * @param Container $container Services.
	 */
	public function register( Container $container ): void {
		unset( $container );
		add_action( 'wp_loaded', array( CronRecorder::class, 'maybe_start' ), PHP_INT_MAX );
	}
}
