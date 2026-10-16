<?php
/**
 * Translation loading helpers.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Support;

defined( 'ABSPATH' ) || exit;

/**
 * Loads the text domain on init, or immediately when the block page is rendered
 * before init (the early firewall exits before init ever fires).
 */
final class I18n {

	/**
	 * Loads translations if not already loaded.
	 */
	public static function load(): void {
		if ( is_textdomain_loaded( 'sentinel-shield' ) ) {
			return;
		}
		load_plugin_textdomain( 'sentinel-shield', false, dirname( plugin_basename( SENTINEL_SHIELD_FILE ) ) . '/languages' );
	}
}
