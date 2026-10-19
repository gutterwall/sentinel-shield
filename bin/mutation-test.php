<?php
/**
 * Mutation test: applies each deliberate defect from tests/mutations.php in
 * turn, runs the tests named for it, and checks that they fail. A defect the
 * tests do not notice ("survived") means a security decision is not really
 * tested; the run then exits with 1.
 *
 * Usage: php bin/mutation-test.php [--only=N[,M...]] [--list]
 *
 * Needs the integration test setup (WP_TESTS_DIR, as for composer
 * test:integration). Source files are changed while it runs and restored
 * afterwards, also when it is interrupted; do not edit them meanwhile.
 *
 * @package SentinelShield
 */

// phpcs:disable -- Developer tool, not shipped in the plugin zip.

$root      = dirname( __DIR__ );
$mutations = require $root . '/tests/mutations.php';
$options   = getopt( '', array( 'only:', 'list' ) );
$only      = isset( $options['only'] ) ? array_map( 'intval', explode( ',', (string) $options['only'] ) ) : array();

if ( isset( $options['list'] ) ) {
	foreach ( $mutations as $i => $m ) {
		printf( "%3d  %-36s %s\n", $i + 1, $m['file'], $m['why'] );
	}
	exit( 0 );
}

// Restore the original file however the run ends.
$original = array();
$restore  = static function () use ( &$original, $root ): void {
	foreach ( $original as $file => $content ) {
		file_put_contents( "$root/$file", $content );
	}
	$original = array();
};
register_shutdown_function( $restore );
if ( function_exists( 'pcntl_signal' ) ) {
	pcntl_async_signals( true );
	foreach ( array( SIGINT, SIGTERM, SIGHUP ) as $signal ) {
		pcntl_signal(
			$signal,
			static function () use ( $restore ): void {
				$restore();
				exit( 130 );
			}
		);
	}
}

$run = static function ( string $args ) use ( $root ): array {
	$cmd = sprintf( 'cd %s && %s vendor/bin/phpunit %s 2>&1', escapeshellarg( $root ), escapeshellarg( PHP_BINARY ), $args );
	exec( $cmd, $out, $code );
	return array( $code, implode( "\n", $out ) );
};

// The tests must pass before anything is changed, or every mutant looks killed.
foreach ( array( '--testsuite unit', '--testsuite integration' ) as $suite ) {
	[ $code, $out ] = $run( $suite );
	if ( 0 !== $code ) {
		fwrite( STDERR, "The tests fail without any mutation ($suite):\n" . substr( $out, -2000 ) . "\n" );
		exit( 2 );
	}
}

$killed   = 0;
$survived = array();
$broken   = array();
$started  = microtime( true );
foreach ( $mutations as $i => $m ) {
	$n = $i + 1;
	if ( $only && ! in_array( $n, $only, true ) ) {
		continue;
	}
	$changes = array( $m['file'] => array( $m['find'], $m['replace'] ) ) + ( $m['also'] ?? array() );
	$problem = '';
	foreach ( $changes as $file => [ $find ] ) {
		$found = substr_count( (string) file_get_contents( "$root/$file" ), $find );
		if ( 1 !== $found ) {
			$problem = sprintf( '#%d %s: the text to change occurs %d times (must be once)', $n, $file, $found );
		}
	}
	if ( '' !== $problem ) {
		$broken[] = $problem;
		continue;
	}
	$t0 = microtime( true );
	foreach ( $changes as $file => [ $find, $replace ] ) {
		$content           = (string) file_get_contents( "$root/$file" );
		$original[ $file ] = $content;
		file_put_contents( "$root/$file", str_replace( $find, $replace, $content ) );
		$lint_out = array();
		exec( sprintf( '%s -l %s 2>&1', escapeshellarg( PHP_BINARY ), escapeshellarg( "$root/$file" ) ), $lint_out, $lint_code );
		if ( 0 !== $lint_code ) {
			$problem = sprintf( '#%d %s: the mutated file does not parse', $n, $file );
		}
	}
	if ( '' !== $problem ) {
		$restore();
		$broken[] = $problem;
		continue;
	}
	[ $unit ] = $run( '--testsuite unit' );
	$code     = $unit;
	if ( 0 === $code ) {
		[ $code ] = $run( '--testsuite integration --filter ' . escapeshellarg( '/' . $m['integration'] . '/' ) );
	}
	$restore();
	$secs = microtime( true ) - $t0;
	if ( 0 === $code ) {
		$survived[] = sprintf( '#%d %s: %s', $n, $m['file'], $m['why'] );
		printf( "  SURVIVED #%-3d %-34s %s (%.1fs)\n", $n, $m['file'], $m['why'], $secs );
	} else {
		++$killed;
		printf( "  killed   #%-3d %-34s %s (%.1fs)\n", $n, $m['file'], $m['why'], $secs );
	}
}

$total = $killed + count( $survived );
printf( "\n%d of %d mutants killed (%.0f%%) in %.0fs.\n", $killed, $total, $total ? 100 * $killed / $total : 0, microtime( true ) - $started );
foreach ( $broken as $line ) {
	fwrite( STDERR, "  BROKEN   $line\n" );
}
if ( $survived ) {
	fwrite( STDERR, "Survived (the tests did not notice):\n  " . implode( "\n  ", $survived ) . "\n" );
}
exit( $survived || $broken ? 1 : 0 );
