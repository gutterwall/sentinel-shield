<?php
/**
 * PHPUnit bootstrap.
 *
 * Unit tests run without WordPress. Integration tests need the WordPress test suite:
 *   bash bin/install-wp-tests.sh wordpress_test root '' localhost latest   (from wp-cli scaffold)
 *   WP_TESTS_DIR=/tmp/wordpress-tests-lib vendor/bin/phpunit --testsuite integration
 *
 * @package SentinelShield
 */

$sentinel_root = dirname( __DIR__ );
require_once $sentinel_root . '/vendor/autoload.php';

$sentinel_wp_tests = getenv( 'WP_TESTS_DIR' );

if ( $sentinel_wp_tests && file_exists( $sentinel_wp_tests . '/includes/functions.php' ) ) {
	define( 'SENTINEL_SHIELD_WP_TESTS', true );
	require_once $sentinel_wp_tests . '/includes/functions.php';
	tests_add_filter(
		'muplugins_loaded',
		static function () use ( $sentinel_root ) {
			require $sentinel_root . '/sentinel-shield.php';
			\SentinelShield\Install\Schema::install();
		}
	);
	require $sentinel_wp_tests . '/includes/bootstrap.php';
} else {
	define( 'SENTINEL_SHIELD_WP_TESTS', false );
	if ( ! defined( 'ABSPATH' ) ) {
		define( 'ABSPATH', sys_get_temp_dir() . '/sentinel-shield-abspath/' );
	}
}
