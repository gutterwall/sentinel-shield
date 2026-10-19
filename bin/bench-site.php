<?php
/**
 * Full-stack performance suite: measures what Sentinel Shield adds to a real
 * WordPress site, and how it holds up under attack, against budgets.
 *
 *   ordinary     uncached pages with and without the plugin: added p50/p95/p99
 *                latency, queries, CPU and peak memory per request
 *   flood        a blocked IP floods while legitimate visitors browse:
 *                legitimate latency and errors, flood throughput
 *   logins       distributed invalid logins: password hashes and database
 *                writes per attempt, latency
 *   rebuild      policy changes while visitors browse: publication time and
 *                lag, memory of a build, visitor latency meanwhile
 *   scan         the malware scan runs while people log in: login latency
 *   audit        the audit endpoint is down, then back: cost of a failed
 *                delivery with a backlog, time to catch up
 *
 * Usage: php bin/bench-site.php <wordpress-path> <site-url> [--quick] [--budgets=tests/perf-budgets.json] [--report=file.json] [--only=a,b]
 *
 * Baseline and plugin runs alternate in random order (A B B A ...) after a
 * warm-up, and medians of the repetitions are compared, so one noisy sample
 * does not decide. Query and write counts are exact and held to their
 * budgets strictly; time budgets are deliberately loose (shared CI runners
 * are noisy) and catch only real regressions. For trustworthy timings use
 * a dedicated, otherwise idle machine.
 *
 * The site should run behind nginx or Apache with PHP-FPM (bin/serve-stack.sh)
 * with enough workers for the concurrency used (12). The test installs
 * bin/bench-probe.php as a must-use plugin while it runs, deactivates and
 * reactivates the plugin, and changes settings. DESTRUCTIVE: use a
 * throwaway site only. Needs wp-cli and PHP's curl extension.
 *
 * @package SentinelShield
 */

// phpcs:disable -- Developer tool, not shipped in the plugin zip.

$args    = array_values( array_filter( array_slice( $argv, 1 ), static fn( $a ) => ! str_starts_with( $a, '--' ) ) );
$opts    = array();
foreach ( array_slice( $argv, 1 ) as $a ) {
	if ( preg_match( '/^--([a-z]+)(?:=(.*))?$/', $a, $m ) ) {
		$opts[ $m[1] ] = $m[2] ?? true;
	}
}
if ( count( $args ) < 2 ) {
	fwrite( STDERR, "Usage: php bin/bench-site.php <wordpress-path> <site-url> [--quick] [--budgets=file] [--report=file] [--only=ordinary,flood,logins,rebuild,scan,audit]\n" );
	exit( 2 );
}
$wp_path = rtrim( $args[0], '/' );
$url     = rtrim( $args[1], '/' );
$quick   = ! empty( $opts['quick'] );
$only    = isset( $opts['only'] ) ? explode( ',', (string) $opts['only'] ) : array( 'ordinary', 'flood', 'logins', 'rebuild', 'scan', 'audit' );
$budgets = json_decode( (string) @file_get_contents( $opts['budgets'] ?? dirname( __DIR__ ) . '/tests/perf-budgets.json' ), true ) ?: array();
$log     = getenv( 'SENTINEL_SHIELD_BENCH_LOG' ) ?: sys_get_temp_dir() . '/sentinel-shield-bench.log';
$reps    = $quick ? 2 : 4;
$n       = $quick ? 150 : 400;
$report  = array( 'time' => gmdate( 'c' ), 'php' => PHP_VERSION, 'site' => $url, 'quick' => $quick, 'results' => array(), 'failures' => array() );

function wp( string $cmd ): string {
	global $wp_path;
	exec( 'wp --path=' . escapeshellarg( $wp_path ) . ' ' . $cmd . ' 2>/dev/null', $out, $code );
	if ( 0 !== $code ) {
		fwrite( STDERR, "wp $cmd failed\n" );
		exit( 1 );
	}
	return trim( implode( "\n", $out ) );
}

function percentile( array $values, float $p ): float {
	if ( ! $values ) {
		return 0.0;
	}
	sort( $values );
	return (float) $values[ (int) min( count( $values ) - 1, floor( $p * count( $values ) ) ) ];
}

function median( array $values ): float {
	return percentile( $values, 0.5 );
}

/**
 * Sends $total requests from $make(i) => [path, post|null, ip] at $concurrency.
 *
 * @return array{lat:list<float>, codes:array<int,int>, ids:list<string>, secs:float}
 */
function load( callable $make, int $total, int $concurrency ): array {
	global $url;
	$multi   = curl_multi_init();
	$started = 0;
	$done    = 0;
	$lat     = array();
	$codes   = array();
	$ids     = array();
	$t0      = microtime( true );
	$add     = static function () use ( &$started, $make, $multi, $url, &$ids ): void {
		[ $path, $post, $ip ] = $make( $started );
		$id                   = 'b' . bin2hex( random_bytes( 6 ) );
		$h                    = curl_init( $url . $path );
		curl_setopt_array(
			$h,
			array(
				CURLOPT_RETURNTRANSFER => true,
				CURLOPT_TIMEOUT        => 60,
				CURLOPT_HTTPHEADER     => array( 'X-Forwarded-For: ' . $ip, 'X-Bench-Id: ' . $id, 'Cookie: wordpress_test_cookie=WP%20Cookie%20check' ),
				CURLOPT_PRIVATE        => (string) microtime( true ),
			)
		);
		if ( null !== $post ) {
			curl_setopt( $h, CURLOPT_POSTFIELDS, http_build_query( $post ) );
		}
		curl_multi_add_handle( $multi, $h );
		$ids[] = $id;
		++$started;
	};
	while ( $started < min( $concurrency, $total ) ) {
		$add();
	}
	do {
		curl_multi_exec( $multi, $running );
		curl_multi_select( $multi, 0.02 );
		while ( $info = curl_multi_info_read( $multi ) ) {
			$h              = $info['handle'];
			$lat[]          = ( microtime( true ) - (float) curl_getinfo( $h, CURLINFO_PRIVATE ) ) * 1000;
			$code           = (int) curl_getinfo( $h, CURLINFO_RESPONSE_CODE );
			$codes[ $code ] = ( $codes[ $code ] ?? 0 ) + 1;
			curl_multi_remove_handle( $multi, $h );
			++$done;
			if ( $started < $total ) {
				$add();
			}
		}
	} while ( $done < $total );
	curl_multi_close( $multi );
	return array( 'lat' => $lat, 'codes' => $codes, 'ids' => $ids, 'secs' => microtime( true ) - $t0 );
}

/** Probe lines for request IDs. */
function probes( array $ids ): array {
	global $log;
	clearstatcache();
	$want = array_flip( $ids );
	$out  = array();
	foreach ( (array) @file( $log, FILE_IGNORE_NEW_LINES ) as $line ) {
		$row = json_decode( $line, true );
		if ( is_array( $row ) && isset( $want[ $row['id'] ] ) ) {
			$out[] = $row;
		}
	}
	return $out;
}

function summary( array $run ): array {
	$p = probes( $run['ids'] );
	return array(
		'p50'     => round( percentile( $run['lat'], 0.5 ), 1 ),
		'p95'     => round( percentile( $run['lat'], 0.95 ), 1 ),
		'p99'     => round( percentile( $run['lat'], 0.99 ), 1 ),
		'rps'     => round( count( $run['lat'] ) / max( 0.001, $run['secs'] ), 1 ),
		'errors'  => array_sum( array_filter( $run['codes'], static fn( $c ) => 0 === $c || $c >= 500, ARRAY_FILTER_USE_KEY ) ),
		'codes'   => $run['codes'],
		'queries' => $p ? round( array_sum( array_column( $p, 'q' ) ) / count( $p ), 2 ) : 0.0,
		'writes'  => $p ? round( array_sum( array_column( $p, 'w' ) ) / count( $p ), 3 ) : 0.0,
		'hashes'  => $p ? array_sum( array_column( $p, 'hash' ) ) : 0,
		'cpu_ms'  => $p ? round( 1000 * median( array_column( $p, 'cpu' ) ), 2 ) : 0.0,
		'mem_mb'  => $p ? round( max( array_column( $p, 'mem' ) ) / 1048576, 1 ) : 0.0,
		'probed'  => count( $p ),
	);
}

/** Records a measurement and checks it against its budget. */
function check( string $key, float $value, string $unit = '' ): void {
	global $budgets, $report;
	$report['results'][ $key ] = $value;
	$limit                     = $budgets[ $key ] ?? null;
	$verdict                   = null === $limit ? '' : ( $value <= (float) $limit ? '  ok' : '  OVER BUDGET' );
	printf( "  %-44s %10s%s%s\n", $key, (string) $value . $unit, null === $limit ? '' : " (budget $limit$unit)", $verdict );
	if ( null !== $limit && $value > (float) $limit ) {
		$report['failures'][] = "$key = $value$unit, budget $limit$unit";
	}
}

$ip = static fn( int $i ): string => '198.51.' . ( 100 + intdiv( $i, 250 ) % 20 ) . '.' . ( 1 + $i % 250 );

// Setup.
$mu = $wp_path . '/wp-content/mu-plugins';
@mkdir( $mu, 0775, true );
copy( __DIR__ . '/bench-probe.php', "$mu/sentinel-shield-bench-probe.php" );
$parent = getmypid();
register_shutdown_function(
	static function () use ( $mu, $parent ): void {
		// Forked helpers exit too; only the main process cleans up.
		if ( getmypid() === $parent ) {
			@unlink( "$mu/sentinel-shield-bench-probe.php" );
		}
	}
);
@unlink( $log );
wp( 'plugin activate sentinel-shield' );
foreach ( array( 'general.test_mode false', 'proxy.mode custom', 'proxy.header X-Forwarded-For', 'proxy.trusted_cidrs 127.0.0.1', 'firewall.early_gate prepend', 'login.max_failures 5' ) as $set ) {
	wp( 'sentinel settings-set ' . $set );
}
wp( 'user delete bench_user --yes || true' );
wp( 'user create bench_user bench@example.org --role=subscriber --user_pass=Bench-pass-1234' );
wp( 'sentinel login-attempts --clear' );
wp( 'sentinel early-gate rebuild' );
$post = (int) wp( 'post list --post_type=post --posts_per_page=1 --format=ids' );
$pages = array( '/', '/?p=' . $post, '/wp-login.php' );
$page  = static fn( int $i ): array => array( $pages[ $i % count( $pages ) ], null, '203.0.113.' . ( 1 + $i % 200 ) );
echo "Sentinel Shield performance suite: $url (" . ( $quick ? 'quick' : 'full' ) . ", $reps repetitions)\n";
$probe = load( $page, 3, 1 );
if ( empty( $probe['codes'][200] ) ) {
	fwrite( STDERR, 'The site does not answer: ' . json_encode( $probe['codes'] ) . "\n" );
	exit( 1 );
}
if ( ! probes( $probe['ids'] ) ) {
	fwrite( STDERR, "The probe did not record anything: is $log writable by PHP and the same file for both?\n" );
	exit( 1 );
}

if ( in_array( 'ordinary', $only, true ) ) {
	echo "Ordinary uncached traffic (concurrency 4)\n";
	load( $page, 60, 4 ); // Warm-up: opcache, database buffers.
	$runs  = array( 'off' => array(), 'on' => array() );
	$order = array();
	for ( $r = 0; $r < $reps; $r++ ) {
		$pair = 0 === mt_rand( 0, 1 ) ? array( 'off', 'on' ) : array( 'on', 'off' );
		foreach ( $pair as $state ) {
			wp( 'plugin ' . ( 'on' === $state ? 'activate' : 'deactivate' ) . ' sentinel-shield' );
			if ( 'on' === $state ) {
				wp( 'sentinel early-gate rebuild' );
			}
			load( $page, 20, 4 );
			$runs[ $state ][] = summary( load( $page, $n, 4 ) );
			$order[]          = $state;
		}
	}
	wp( 'plugin activate sentinel-shield' );
	wp( 'sentinel early-gate rebuild' );
	$med = static fn( string $state, string $k ): float => median( array_column( $runs[ $state ], $k ) );
	printf( "  order: %s\n", implode( ' ', $order ) );
	foreach ( array( 'p50', 'p95', 'p99' ) as $k ) {
		printf( "  %s: %.1f ms without, %.1f ms with\n", $k, $med( 'off', $k ), $med( 'on', $k ) );
	}
	check( 'ordinary.added_p50_ms', round( max( 0, $med( 'on', 'p50' ) - $med( 'off', 'p50' ) ), 1 ), ' ms' );
	check( 'ordinary.added_p95_ms', round( max( 0, $med( 'on', 'p95' ) - $med( 'off', 'p95' ) ), 1 ), ' ms' );
	check( 'ordinary.added_queries', round( $med( 'on', 'queries' ) - $med( 'off', 'queries' ), 2 ) );
	check( 'ordinary.writes_per_request', $med( 'on', 'writes' ) );
	check( 'ordinary.added_cpu_ms', round( max( 0, $med( 'on', 'cpu_ms' ) - $med( 'off', 'cpu_ms' ) ), 2 ), ' ms' );
	check( 'ordinary.added_peak_memory_mb', round( max( 0, $med( 'on', 'mem_mb' ) - $med( 'off', 'mem_mb' ) ), 1 ), ' MB' );
	check( 'ordinary.errors', (float) array_sum( array_column( $runs['on'], 'errors' ) ) );
}

if ( in_array( 'flood', $only, true ) ) {
	echo "Blocked flood alongside legitimate traffic\n";
	wp( 'sentinel block 192.0.2.66 --reason=bench' );
	wp( 'sentinel early-gate rebuild' );
	$alone  = summary( load( $page, $n, 2 ) );
	$flood  = array();
	$legit  = null;
	$pid    = pcntl_fork();
	if ( 0 === $pid ) {
		load( static fn( int $i ): array => array( '/', null, '192.0.2.66' ), $n * 10, 10 );
		exit( 0 );
	}
	usleep( 200000 );
	$legit = summary( load( $page, $n, 2 ) );
	pcntl_waitpid( $pid, $status );
	$flood = summary( load( static fn( int $i ): array => array( '/', null, '192.0.2.66' ), 500, 10 ) );
	wp( 'sentinel unblock 192.0.2.66' );
	printf( "  legitimate p95: %.1f ms alone, %.1f ms during the flood; flood refused at %.0f req/s\n", $alone['p95'], $legit['p95'], $flood['rps'] );
	check( 'flood.legit_p95_ratio', round( $legit['p95'] / max( 1, $alone['p95'] ), 2 ) );
	check( 'flood.legit_errors', (float) $legit['errors'] );
	check( 'flood.reached_wordpress', (float) $flood['probed'] );
	check( 'flood.non_403', (float) ( 500 - ( $flood['codes'][403] ?? 0 ) ) );
}

if ( in_array( 'logins', $only, true ) ) {
	echo "Distributed invalid logins\n";
	wp( 'sentinel login-attempts --clear' );
	$attempts = $quick ? 300 : 900;
	// 60% guess a real account, 40% names that do not exist; each IP tries 3 times.
	$guess = static function ( int $i ) use ( $ip ): array {
		$user = 0 === $i % 5 || 1 === $i % 5 ? 'nobody' . ( $i % 37 ) : 'bench_user';
		return array( '/wp-login.php', array( 'log' => $user, 'pwd' => 'wrong-' . $i, 'testcookie' => '1' ), $ip( intdiv( $i, 3 ) ) );
	};
	$s = summary( load( $guess, $attempts, 8 ) );
	printf( "  %d attempts from %d IPs: p95 %.1f ms, %d password hashes, %.2f writes per attempt (HTTP %s)\n", $attempts, intdiv( $attempts, 3 ), $s['p95'], $s['hashes'], $s['writes'], json_encode( $s['codes'] ) );
	check( 'logins.hashes_per_attempt', round( $s['hashes'] / max( 1, $s['probed'] ), 3 ) );
	check( 'logins.writes_per_attempt', $s['writes'] );
	check( 'logins.queries_per_attempt', $s['queries'] );
	check( 'logins.p95_ms', $s['p95'], ' ms' );
	check( 'logins.errors', (float) $s['errors'] );
	// Locked out: the account limit now protects bench_user from unknown IPs.
	$after = summary( load( static fn( int $i ): array => array( '/wp-login.php', array( 'log' => 'bench_user', 'pwd' => 'wrong', 'testcookie' => '1' ), '203.0.113.250' ), 20, 2 ) );
	check( 'logins.hashes_once_limited', (float) $after['hashes'] );
	wp( 'sentinel login-attempts --clear' );
	exec( 'wp --path=' . escapeshellarg( $wp_path ) . ' eval ' . escapeshellarg( 'foreach ( range( 0, ' . intdiv( $attempts, 3 ) . ' ) as $i ) { SentinelShield\Plugin::instance()->container()->get( SentinelShield\Lockout\Unblocker::class )->unblock( "198.51." . ( 100 + intdiv( $i, 250 ) % 20 ) . "." . ( 1 + $i % 250 ), false, 0, 0, "cli" ); }' ) . ' 2>/dev/null' );
}

if ( in_array( 'rebuild', $only, true ) ) {
	echo "Policy rebuilds under traffic\n";
	$changes = $quick ? 5 : 15;
	$pid     = pcntl_fork();
	if ( 0 === $pid ) {
		for ( $i = 0; $i < $changes; $i++ ) {
			exec( 'wp --path=' . escapeshellarg( $wp_path ) . ' sentinel block 192.0.2.' . ( 100 + $i ) . ' --reason=bench 2>/dev/null' );
			usleep( 300000 );
		}
		exit( 0 );
	}
	$during = summary( load( $page, $n, 4 ) );
	pcntl_waitpid( $pid, $status );
	$build = json_decode(
		wp(
			'eval ' . escapeshellarg(
				'$r = SentinelShield\Plugin::instance()->container()->get( SentinelShield\Repository\BlockRepository::class ); for ( $i = 0; $i < 20000; $i++ ) { $r->add( "block", SentinelShield\Net\Cidr::parse( "10." . intdiv( 2 * $i, 256 ) % 256 . "." . ( 2 * $i ) % 256 . ".0/24" ), "bench-big", "manual" ); } /* every other /24: 20000 separate ranges */ SentinelShield\Plugin::instance()->container()->get( SentinelShield\Firewall\RuleCache::class )->flush(); $m0 = memory_get_usage(); $t = microtime( true ); $s = SentinelShield\Plugin::instance()->container()->get( SentinelShield\Firewall\EarlyGate::class )->rebuild(); echo json_encode( array( "secs" => microtime( true ) - $t, "mem" => ( memory_get_peak_usage() - $m0 ) / 1048576, "ok" => $s["generation"] === $s["published"], "pending" => SentinelShield\Plugin::instance()->container()->get( SentinelShield\Firewall\EarlyGate::class )->publication()["pending"] ) );'
			)
		),
		true
	);
	$lag = json_decode( wp( 'eval ' . escapeshellarg( 'echo json_encode( SentinelShield\Plugin::instance()->container()->get( SentinelShield\Firewall\EarlyGate::class )->publication() );' ) ), true );
	printf( "  visitors p95 %.1f ms during %d rule changes; a 20000-range build took %.2f s and %.1f MB\n", $during['p95'], $changes, $build['secs'], $build['mem'] );
	check( 'rebuild.visitor_p95_ms', $during['p95'], ' ms' );
	check( 'rebuild.visitor_errors', (float) $during['errors'] );
	check( 'rebuild.build_20000_seconds', round( $build['secs'], 2 ), ' s' );
	check( 'rebuild.build_20000_memory_mb', round( $build['mem'], 1 ), ' MB' );
	check( 'rebuild.unpublished_after_build', ( $build['ok'] && ! $build['pending'] ) ? 0.0 : 1.0 );
	check( 'rebuild.overdue', ! empty( $lag['overdue'] ) ? 1.0 : 0.0 );
	exec( 'wp --path=' . escapeshellarg( $wp_path ) . ' eval ' . escapeshellarg( 'global $wpdb; $r = SentinelShield\Plugin::instance()->container()->get( SentinelShield\Repository\BlockRepository::class ); $wpdb->query( $wpdb->prepare( "DELETE FROM %i WHERE reason IN (%s, %s)", $r->table(), "bench", "bench-big" ) ); SentinelShield\Plugin::instance()->container()->get( SentinelShield\Firewall\RuleCache::class )->flush(); SentinelShield\Plugin::instance()->container()->get( SentinelShield\Firewall\EarlyGate::class )->rebuild();' ) . ' 2>/dev/null' );
}

if ( in_array( 'scan', $only, true ) ) {
	echo "Malware scan alongside logins\n";
	$login  = static fn( int $i ): array => array( '/wp-login.php', array( 'log' => 'bench_user', 'pwd' => 'Bench-pass-1234', 'testcookie' => '1' ), '203.0.113.' . ( 1 + $i % 200 ) );
	$alone  = summary( load( $login, intdiv( $n, 2 ), 2 ) );
	$pid    = pcntl_fork();
	if ( 0 === $pid ) {
		exec( 'wp --path=' . escapeshellarg( $wp_path ) . ' sentinel scan 2>/dev/null >/dev/null' );
		exit( 0 );
	}
	$during = summary( load( $login, intdiv( $n, 2 ), 2 ) );
	pcntl_waitpid( $pid, $status );
	printf( "  login p95 %.1f ms alone, %.1f ms during the scan\n", $alone['p95'], $during['p95'] );
	check( 'scan.login_p95_ratio', round( $during['p95'] / max( 1, $alone['p95'] ), 2 ) );
	check( 'scan.login_errors', (float) $during['errors'] );
}

if ( in_array( 'audit', $only, true ) ) {
	echo "Audit endpoint outage and recovery\n";
	// The endpoint answers through a filter: down (refused), then up.
	$down = 'add_filter( "pre_http_request", static fn( $p, $a, $u ) => str_contains( $u, "audit.invalid" ) ? new WP_Error( "http_request_failed", "Connection refused" ) : $p, 10, 3 );';
	$up   = 'add_filter( "pre_http_request", static fn( $p, $a, $u ) => str_contains( $u, "audit.invalid" ) ? array( "headers" => array(), "body" => "ok", "response" => array( "code" => 200, "message" => "OK" ), "cookies" => array(), "filename" => null ) : $p, 10, 3 );';
	$use  = '$a = SentinelShield\Plugin::instance()->container()->get( SentinelShield\Audit\AuditExporter::class );';
	wp( 'sentinel settings-set audit.webhook_url https://audit.invalid/in' );
	wp( 'sentinel settings-set audit.scope security' );
	wp( 'eval ' . escapeshellarg( $down . ' $e = SentinelShield\Plugin::instance()->container()->get( SentinelShield\Repository\EventRepository::class ); for ( $i = 0; $i < 3000; $i++ ) { $e->log( "config_change", array( "ip" => "127.0.0.1", "module" => "core", "reason" => "bench" ) ); }' ) );
	$fail = json_decode( wp( 'eval ' . escapeshellarg( $down . $use . ' $t = microtime( true ); $s = $a->run( 5 ); echo json_encode( array( "secs" => microtime( true ) - $t, "backlog" => $a->backlog(), "next" => (int) ( $s["next_try"] ?? 0 ) - time() ) );' ) ), true );
	$t    = microtime( true );
	$back = json_decode( wp( 'eval ' . escapeshellarg( $up . $use . ' $s = SentinelShield\Audit\AuditExporter::state(); $s["next_try"] = 0; update_site_option( SentinelShield\Audit\AuditExporter::STATE, $s ); $t = microtime( true ); $a->run( 15 ); echo json_encode( array( "secs" => microtime( true ) - $t, "backlog" => $a->backlog() ) );' ) ), true );
	wp( 'sentinel settings-set audit.webhook_url ""' );
	printf( "  down: a failed delivery took %.3f s with %d events waiting (next try in %d s); back up: %d left after %.2f s\n", $fail['secs'], $fail['backlog'], $fail['next'], $back['backlog'], $back['secs'] );
	check( 'audit.failed_delivery_seconds', round( $fail['secs'], 3 ), ' s' );
	check( 'audit.catch_up_3000_seconds', round( $back['secs'], 2 ), ' s' );
	check( 'audit.backlog_left', (float) $back['backlog'] );
}

wp( 'user delete bench_user --yes' );
if ( isset( $opts['report'] ) ) {
	file_put_contents( (string) $opts['report'], json_encode( $report, JSON_PRETTY_PRINT ) . "\n" );
}
if ( $report['failures'] ) {
	echo "\nOver budget:\n  " . implode( "\n  ", $report['failures'] ) . "\n";
	exit( 1 );
}
echo "\nAll measurements within budget.\n";
