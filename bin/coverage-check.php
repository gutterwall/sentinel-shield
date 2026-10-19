<?php
/**
 * Checks coverage against the floors in tests/coverage-baseline.json: line
 * coverage overall and per security-critical area, and branch coverage
 * where a branch report is given. A change may not lower any of them.
 *
 * Usage: php bin/coverage-check.php <clover.xml> [--branches=branch.json] [--update] [--summary=file.md]
 *   --update   raise the floors to the current values (never lowers them)
 *   --summary  also write the table as Markdown (for the CI job summary)
 *
 * The floors are what the suite reaches today, not the goal: the goals
 * (in the same file) are 90% of lines overall and 95% of branches in the
 * security-critical areas, and are reported here without failing the run.
 *
 * @package SentinelShield
 */

// phpcs:disable -- Developer tool, not shipped in the plugin zip.

$args = array_values( array_filter( array_slice( $argv, 1 ), static fn( $a ) => ! str_starts_with( $a, '--' ) ) );
$opts = array();
foreach ( array_slice( $argv, 1 ) as $a ) {
	if ( preg_match( '/^--([a-z]+)(?:=(.*))?$/', $a, $m ) ) {
		$opts[ $m[1] ] = $m[2] ?? true;
	}
}
if ( ! $args ) {
	fwrite( STDERR, "Usage: php bin/coverage-check.php <clover.xml> [--branches=branch.json] [--update] [--summary=file.md]\n" );
	exit( 2 );
}
$root     = dirname( __DIR__ ) . '/';
$baseline = $root . 'tests/coverage-baseline.json';
$config   = json_decode( (string) file_get_contents( $baseline ), true );
$xml      = simplexml_load_file( $args[0] );
if ( false === $xml || ! is_array( $config ) ) {
	fwrite( STDERR, "Cannot read the coverage report or the baseline.\n" );
	exit( 2 );
}

// Lines per file from Clover.
$lines = array();
foreach ( $xml->xpath( '//file' ) as $file ) {
	$name = str_replace( $root, '', (string) $file['name'] );
	$m    = $file->metrics;
	$lines[ $name ] = array( (int) $m['coveredstatements'], (int) $m['statements'] );
}
$branches = isset( $opts['branches'] ) && is_file( (string) $opts['branches'] ) ? (array) json_decode( (string) file_get_contents( (string) $opts['branches'] ), true ) : array();

$in = static function ( string $file, array $paths ): bool {
	foreach ( $paths as $path ) {
		if ( $file === $path || ( str_ends_with( $path, '/' ) && str_starts_with( $file, $path ) ) ) {
			return true;
		}
	}
	return false;
};

$failed = array();
$rows   = array();
foreach ( $config['groups'] as $group => &$spec ) {
	$covered = 0;
	$total   = 0;
	foreach ( $lines as $file => [ $c, $t ] ) {
		if ( $in( $file, $spec['paths'] ) ) {
			$covered += $c;
			$total   += $t;
		}
	}
	$line_pct = $total ? round( 100 * $covered / $total, 1 ) : 0.0;
	$bhit     = 0;
	$btotal   = 0;
	foreach ( $branches as $file => $b ) {
		if ( $in( (string) $file, $spec['paths'] ) ) {
			$bhit   += (int) $b['hit'];
			$btotal += (int) $b['branches'];
		}
	}
	$branch_pct = $btotal ? round( 100 * $bhit / $btotal, 1 ) : null;
	$rows[]     = array( $group, $line_pct, $covered, $total, $spec['lines'] ?? null, $branch_pct, $spec['branches'] ?? null );
	if ( isset( $spec['lines'] ) && $line_pct < (float) $spec['lines'] ) {
		$failed[] = sprintf( '%s: %.1f%% of lines, below the floor of %.1f%%', $group, $line_pct, $spec['lines'] );
	}
	if ( null !== $branch_pct && isset( $spec['branches'] ) && $branch_pct < (float) $spec['branches'] ) {
		$failed[] = sprintf( '%s: %.1f%% of branches, below the floor of %.1f%%', $group, $branch_pct, $spec['branches'] );
	}
	if ( isset( $opts['update'] ) ) {
		$spec['lines'] = max( (float) ( $spec['lines'] ?? 0 ), floor( 2 * $line_pct - 1 ) / 2 );
		if ( null !== $branch_pct ) {
			$spec['branches'] = max( (float) ( $spec['branches'] ?? 0 ), floor( 2 * $branch_pct - 1 ) / 2 );
		}
	}
}
unset( $spec );

$table = "| Area | Lines | Floor | Branches | Floor | Goal |\n|---|---|---|---|---|---|\n";
foreach ( $rows as [ $group, $lp, $c, $t, $lf, $bp, $bf ] ) {
	$goal   = 'overall' === $group ? $config['goals']['overall_lines'] . '% lines' : $config['goals']['security_branches'] . '% branches';
	$table .= sprintf( "| %s | %.1f%% (%d/%d) | %s | %s | %s | %s |\n", $group, $lp, $c, $t, null === $lf ? '—' : $lf . '%', null === $bp ? 'not measured' : $bp . '%', null === $bf ? '—' : $bf . '%', $goal );
}
echo $table;
if ( isset( $opts['summary'] ) ) {
	file_put_contents( (string) $opts['summary'], "### Coverage\n\n" . $table . "\nFloors are today's values; a change may not go below them. Goals are targets, not yet enforced.\n", FILE_APPEND );
}
if ( isset( $opts['update'] ) ) {
	file_put_contents( $baseline, json_encode( $config, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES ) . "\n" );
	echo "Floors updated in tests/coverage-baseline.json.\n";
}
if ( $failed ) {
	fwrite( STDERR, "\nCoverage went down:\n  " . implode( "\n  ", $failed ) . "\n" );
	exit( 1 );
}
echo "\nNo area is below its floor.\n";
