<?php
/**
 * Branch coverage for a whole test run, collected once (auto_prepend_file):
 * PHPUnit's own path coverage re-processes every path after each test,
 * which takes hours on this suite. Needs Xdebug in coverage mode; writes
 * {file: {branches, hit}} for the files under src/ to the JSON file named
 * by SENTINEL_SHIELD_BRANCH_OUT. bin/coverage-check.php reads it.
 *
 * @package SentinelShield
 */

// phpcs:disable -- Test tool, not shipped in the plugin zip.

if ( function_exists( 'xdebug_start_code_coverage' ) && getenv( 'SENTINEL_SHIELD_BRANCH_OUT' ) ) {
	// Only the plugin's own code is instrumented (WordPress itself would take hours).
	xdebug_set_filter( XDEBUG_FILTER_CODE_COVERAGE, XDEBUG_PATH_INCLUDE, array( dirname( __DIR__, 2 ) . '/src/', dirname( __DIR__, 2 ) . '/early-gate.php' ) );
	xdebug_start_code_coverage( XDEBUG_CC_UNUSED | XDEBUG_CC_DEAD_CODE | XDEBUG_CC_BRANCH_CHECK );
	register_shutdown_function(
		static function (): void {
			$root = dirname( __DIR__, 2 ) . '/';
			$out  = array();
			foreach ( xdebug_get_code_coverage() as $file => $data ) {
				if ( ! str_starts_with( $file, $root . 'src/' ) && $file !== $root . 'early-gate.php' ) {
					continue;
				}
				$branches = 0;
				$hit      = 0;
				foreach ( (array) ( $data['functions'] ?? array() ) as $function ) {
					foreach ( (array) ( $function['branches'] ?? array() ) as $branch ) {
						// Each branch exit is an edge to cover (a condition has two).
						$exits = max( 1, count( (array) ( $branch['out'] ?? array() ) ) );
						foreach ( (array) ( $branch['out_hit'] ?? array() ) as $i => $taken ) {
							$hit += $taken ? 1 : 0;
						}
						$branches += $exits;
					}
				}
				$out[ substr( $file, strlen( $root ) ) ] = array(
					'branches' => $branches,
					'hit'      => $hit,
				);
			}
			$path     = (string) getenv( 'SENTINEL_SHIELD_BRANCH_OUT' );
			$existing = is_file( $path ) ? (array) json_decode( (string) file_get_contents( $path ), true ) : array();
			// Several runs (unit, integration, multisite) add up: a branch counts as hit if any run hit it.
			foreach ( $out as $file => $row ) {
				$prev            = $existing[ $file ] ?? array( 'branches' => 0, 'hit' => 0 );
				$existing[ $file ] = array(
					'branches' => max( $prev['branches'], $row['branches'] ),
					'hit'      => max( $prev['hit'], $row['hit'] ),
				);
			}
			file_put_contents( $path, json_encode( $existing, JSON_PRETTY_PRINT ) );
		}
	);
}
