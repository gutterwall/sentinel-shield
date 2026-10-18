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
 * Leaves language packs to WordPress's just-in-time loading, loads a translation
 * shipped in the plugin's languages folder, and loads immediately when the block
 * page is rendered before init (the firewall exits before init ever fires).
 */
final class I18n {

	/**
	 * Loads translations if not already loaded.
	 */
	public static function load(): void {
		if ( is_textdomain_loaded( 'sentinel-shield' ) ) {
			return;
		}
		if ( did_action( 'after_setup_theme' ) || doing_action( 'after_setup_theme' ) ) {
			// WordPress loads language packs (wp-content/languages/plugins) just in
			// time; only a translation shipped in the plugin's own folder needs help.
			$locale = determine_locale();
			$file   = dirname( SENTINEL_SHIELD_FILE ) . '/languages/sentinel-shield-' . $locale . '.mo';
			if ( ! is_readable( WP_LANG_DIR . '/plugins/sentinel-shield-' . $locale . '.mo' ) && is_readable( $file ) ) {
				load_textdomain( 'sentinel-shield', $file, $locale );
			}
			return;
		}
		self::load_early();
	}

	/**
	 * For responses sent before after_setup_theme (the block page). Since WordPress
	 * 6.7, load_plugin_textdomain() and just-in-time loading warn this early, so the
	 * translation file is loaded directly; without one, just-in-time loading is
	 * switched off for the rest of this request, which ends with the block page.
	 */
	private static function load_early(): void {
		$locale = determine_locale();
		$files  = array(
			WP_LANG_DIR . '/plugins/sentinel-shield-' . $locale . '.mo',
			dirname( SENTINEL_SHIELD_FILE ) . '/languages/sentinel-shield-' . $locale . '.mo',
		);
		foreach ( $files as $file ) {
			if ( load_textdomain( 'sentinel-shield', $file, $locale ) ) {
				return;
			}
		}
		global $l10n_unloaded;
		$l10n_unloaded                    = (array) $l10n_unloaded; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited, WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- Core's own just-in-time opt-out list.
		$l10n_unloaded['sentinel-shield'] = true; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited, WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- See above.
	}
}
