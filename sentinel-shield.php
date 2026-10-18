<?php
/**
 * Plugin Name:       Sentinel Shield
 * Plugin URI:        https://github.com/gutterwall/sentinel-shield
 * Description:       Self-hosted firewall, brute-force protection, IP blocklists and hardening for WordPress. No paid cloud service required.
 * Version:           0.8.1
 * Requires at least: 6.4
 * Requires PHP:      8.1
 * Author:            Sentinel Shield Contributors
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       sentinel-shield
 * Domain Path:       /languages
 * Network:           true
 *
 * @package SentinelShield
 */

// This file must stay parseable on old PHP versions so the version notice can be shown.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'SENTINEL_SHIELD_VERSION', '0.8.1' );
define( 'SENTINEL_SHIELD_FILE', __FILE__ );
define( 'SENTINEL_SHIELD_DIR', __DIR__ );

if ( version_compare( PHP_VERSION, '8.1', '<' ) ) {
	add_action(
		'admin_notices',
		function () {
			echo '<div class="notice notice-error"><p>' . esc_html__( 'Sentinel Shield requires PHP 8.1 or newer. The plugin is inactive until PHP is upgraded.', 'sentinel-shield' ) . '</p></div>';
		}
	);
	return;
}

if ( is_readable( __DIR__ . '/vendor/autoload.php' ) ) {
	require_once __DIR__ . '/vendor/autoload.php';
} else {
	// Fallback PSR-4 autoloader so the plugin runs without `composer install` (no runtime dependencies in this phase).
	spl_autoload_register(
		function ( $class_name ) {
			$prefix = 'SentinelShield\\';
			if ( 0 !== strncmp( $class_name, $prefix, strlen( $prefix ) ) ) {
				return;
			}
			$file = __DIR__ . '/src/' . str_replace( '\\', '/', substr( $class_name, strlen( $prefix ) ) ) . '.php';
			if ( is_readable( $file ) ) {
				require_once $file;
			}
		}
	);
}

register_activation_hook( __FILE__, array( \SentinelShield\Install\Installer::class, 'activate' ) );
register_deactivation_hook( __FILE__, array( \SentinelShield\Install\Installer::class, 'deactivate' ) );

\SentinelShield\Plugin::instance()->boot();
