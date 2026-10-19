<?php
/**
 * Line coverage of the early firewall in the PHP servers the HTTP tests
 * start (EarlyGateTest). Used instead of early-gate.php as auto_prepend_file
 * when SENTINEL_SHIELD_SUBPROCESS_COVERAGE names a folder: starts coverage
 * (PCOV or Xdebug), runs the gate, and on shutdown (also after the gate's
 * exit) saves the request's coverage there for phpcov merge.
 *
 * @package SentinelShield
 */

// phpcs:disable -- Test tool, not shipped in the plugin zip.

$sentinel_shield_cov_dir = (string) getenv( 'SENTINEL_SHIELD_SUBPROCESS_COVERAGE' );
if ( '' !== $sentinel_shield_cov_dir && is_dir( $sentinel_shield_cov_dir ) ) {
	require dirname( __DIR__, 2 ) . '/vendor/autoload.php';
	$sentinel_shield_cov_filter = new SebastianBergmann\CodeCoverage\Filter();
	$sentinel_shield_cov_filter->includeFile( dirname( __DIR__, 2 ) . '/early-gate.php' );
	$sentinel_shield_cov = new SebastianBergmann\CodeCoverage\CodeCoverage( ( new SebastianBergmann\CodeCoverage\Driver\Selector() )->forLineCoverage( $sentinel_shield_cov_filter ), $sentinel_shield_cov_filter );
	$sentinel_shield_cov->start( 'early firewall over HTTP' );
	register_shutdown_function(
		static function () use ( $sentinel_shield_cov, $sentinel_shield_cov_dir ): void {
			$sentinel_shield_cov->stop();
			( new SebastianBergmann\CodeCoverage\Report\PHP() )->process( $sentinel_shield_cov, $sentinel_shield_cov_dir . '/http-' . getmypid() . '-' . bin2hex( random_bytes( 4 ) ) . '.cov' );
		}
	);
	unset( $sentinel_shield_cov_filter, $sentinel_shield_cov, $sentinel_shield_cov_dir );
}
require dirname( __DIR__, 2 ) . '/early-gate.php';
