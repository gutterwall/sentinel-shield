<?php
/**
 * Test-only must-use plugin for bin/bench-site.php (never shipped, removed
 * after each run): for requests carrying "X-Bench-Id", records the database
 * queries and writes, password hash checks, CPU time and peak memory of the
 * request as one JSON line in the file named by SENTINEL_SHIELD_BENCH_LOG
 * (default: <temp dir>/sentinel-shield-bench.log).
 *
 * @package SentinelShield
 */

// phpcs:disable -- Developer tool, not shipped in the plugin zip.

if ( isset( $_SERVER['HTTP_X_BENCH_ID'] ) && preg_match( '/^[a-z0-9-]{1,64}$/', (string) $_SERVER['HTTP_X_BENCH_ID'] ) ) {
	( static function (): void {
		$usage = getrusage();
		$stats = array(
			'id'    => (string) $_SERVER['HTTP_X_BENCH_ID'],
			'q'     => 0,
			'w'     => 0,
			'hash'  => 0,
			'cpu0'  => $usage['ru_utime.tv_sec'] + $usage['ru_utime.tv_usec'] / 1e6 + $usage['ru_stime.tv_sec'] + $usage['ru_stime.tv_usec'] / 1e6,
		);
		add_filter(
			'query',
			static function ( $query ) use ( &$stats ) {
				++$stats['q'];
				if ( preg_match( '/^\s*(INSERT|UPDATE|DELETE|REPLACE)\b/i', (string) $query ) ) {
					++$stats['w'];
				}
				return $query;
			}
		);
		add_filter(
			'check_password',
			static function ( $check ) use ( &$stats ) {
				++$stats['hash'];
				return $check;
			},
			1
		);
		register_shutdown_function(
			static function () use ( &$stats ): void {
				$usage = getrusage();
				$cpu   = $usage['ru_utime.tv_sec'] + $usage['ru_utime.tv_usec'] / 1e6 + $usage['ru_stime.tv_sec'] + $usage['ru_stime.tv_usec'] / 1e6;
				$line  = json_encode(
					array(
						'id'   => $stats['id'],
						'q'    => $stats['q'],
						'w'    => $stats['w'],
						'hash' => $stats['hash'],
						'cpu'  => round( $cpu - $stats['cpu0'], 5 ),
						'mem'  => memory_get_peak_usage(),
						'code' => http_response_code(),
					)
				);
				$log = getenv( 'SENTINEL_SHIELD_BENCH_LOG' ) ?: sys_get_temp_dir() . '/sentinel-shield-bench.log';
				@file_put_contents( $log, $line . "\n", FILE_APPEND | LOCK_EX );
			}
		);
	} )();
}
