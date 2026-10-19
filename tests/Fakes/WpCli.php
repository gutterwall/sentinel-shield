<?php
/**
 * Stand-in for WP-CLI in the integration tests (only when WP-CLI itself is
 * not loaded): records what commands print and turns error() and halt() into
 * exceptions, so commands can be run in-process.
 *
 * @package SentinelShield
 */

// phpcs:disable -- Test double.

namespace SentinelShield\Tests\Fakes {
	/** WP_CLI::error(). */
	final class CliError extends \RuntimeException {}
	/** WP_CLI::halt(). */
	final class CliHalt extends \RuntimeException {}
}

namespace {
	if ( ! class_exists( 'WP_CLI' ) ) {
		final class WP_CLI {
			/** @var list<array{0:string, 1:string}> */
			public static array $out = array();
			public static function success( $m ) { self::$out[] = array( 'success', (string) $m ); }
			public static function warning( $m ) { self::$out[] = array( 'warning', (string) $m ); }
			public static function log( $m ) { self::$out[] = array( 'log', (string) $m ); }
			public static function line( $m = '' ) { self::$out[] = array( 'line', (string) $m ); }
			public static function error( $m, $exit = true ) { throw new SentinelShield\Tests\Fakes\CliError( is_string( $m ) ? $m : wp_json_encode( $m ) ); }
			public static function halt( $code ) { throw new SentinelShield\Tests\Fakes\CliHalt( (string) $code, (int) $code ); }
			public static function add_command( ...$args ) {}
		}
	}
}

namespace WP_CLI\Utils {
	if ( ! function_exists( 'WP_CLI\Utils\format_items' ) ) {
		function format_items( $format, $items, $fields ) {
			\WP_CLI::$out[] = array( 'items', (string) wp_json_encode( array_values( is_array( $items ) ? $items : iterator_to_array( $items ) ) ) );
		}
	}
}
