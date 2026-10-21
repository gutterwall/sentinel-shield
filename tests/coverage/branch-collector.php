<?php
/**
 * Branch coverage for a whole test run, collected once (auto_prepend_file):
 * PHPUnit's own path coverage re-processes every path after each test,
 * which takes hours on this suite. Needs Xdebug in coverage mode; writes
 * {file: {branches, hit, edges}} for the files under src/ (and the two top files)
 * to the JSON file named by SENTINEL_SHIELD_BRANCH_OUT, merging with what is
 * there. bin/coverage-check.php reads branches and hit.
 *
 * @package SentinelShield
 */

// phpcs:disable -- Test tool, not shipped in the plugin zip.

if ( function_exists( 'xdebug_start_code_coverage' ) && getenv( 'SENTINEL_SHIELD_BRANCH_OUT' ) ) {
	// Only the plugin's own code is instrumented (WordPress itself would take hours).
	xdebug_set_filter( XDEBUG_FILTER_CODE_COVERAGE, XDEBUG_PATH_INCLUDE, array( dirname( __DIR__, 2 ) . '/src/', dirname( __DIR__, 2 ) . '/early-gate.php', dirname( __DIR__, 2 ) . '/sentinel-shield.php' ) );
	xdebug_start_code_coverage( XDEBUG_CC_UNUSED | XDEBUG_CC_DEAD_CODE | XDEBUG_CC_BRANCH_CHECK );
	register_shutdown_function(
		static function (): void {
			$root = dirname( __DIR__, 2 ) . '/';
			$out  = array();
			foreach ( xdebug_get_code_coverage() as $file => $data ) {
				if ( ! str_starts_with( $file, $root . 'src/' ) && ! in_array( $file, array( $root . 'early-gate.php', $root . 'sentinel-shield.php' ), true ) ) {
					continue;
				}
				// Each branch exit is an edge to cover (a condition has two), keyed so
				// that several runs and requests merge as a union.
				$edges = array();
				foreach ( (array) ( $data['functions'] ?? array() ) as $fname => $function ) {
					foreach ( (array) ( $function['branches'] ?? array() ) as $bid => $branch ) {
						$exits = max( 1, count( (array) ( $branch['out'] ?? array() ) ) );
						for ( $i = 0; $i < $exits; $i++ ) {
							$edges[ $fname . '#' . $bid . '#' . $i ] = ! empty( $branch['out_hit'][ $i ] );
						}
					}
				}
				$out[ substr( $file, strlen( $root ) ) ] = $edges;
			}
			$path = (string) getenv( 'SENTINEL_SHIELD_BRANCH_OUT' );
			// The test run and the PHP servers its HTTP tests start finish at
			// different times: one writer at a time, each adding to the others.
			$lock = fopen( $path . '.lock', 'c' );
			if ( false !== $lock ) {
				flock( $lock, LOCK_EX );
			}
			clearstatcache( true, $path );
			$existing = is_file( $path ) ? (array) json_decode( (string) file_get_contents( $path ), true ) : array();
			// Several runs and requests add up: an edge counts as hit if any of them hit it.
			foreach ( $out as $file => $edges ) {
				$union = (array) ( $existing[ $file ]['edges'] ?? array() );
				foreach ( $edges as $key => $hit ) {
					$union[ $key ] = ! empty( $union[ $key ] ) || $hit;
				}
				$existing[ $file ] = array(
					'branches' => count( $union ),
					'hit'      => count( array_filter( $union ) ),
					'edges'    => $union,
				);
			}
			file_put_contents( $path, json_encode( $existing, JSON_PRETTY_PRINT ) );
			if ( false !== $lock ) {
				flock( $lock, LOCK_UN );
				fclose( $lock );
			}
		}
	);
}
