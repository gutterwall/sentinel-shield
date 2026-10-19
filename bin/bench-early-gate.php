<?php
/**
 * Benchmarks the early firewall (early-gate.php) without WordPress.
 *
 * Builds a synthetic snapshot (block and allow range files in the plugin's
 * binary format, plus gate.json), serves a one-line PHP page with PHP's
 * built-in server (several workers), and measures requests per second:
 *
 *   baseline   no early firewall
 *   pass       early firewall, visitor not listed (every request is checked)
 *   flood      early firewall, visitor blocked (403 page + sampled block log)
 *
 * Usage: php bin/bench-early-gate.php [requests=4000] [concurrency=16] [ranges=50000]
 *
 * Numbers depend on the machine; compare them with each other, not across hosts.
 *
 * @package SentinelShield
 */

// phpcs:disable -- Developer tool, not shipped in the plugin zip.

$requests    = (int) ( $argv[1] ?? 4000 );
$concurrency = (int) ( $argv[2] ?? 16 );
$ranges      = (int) ( $argv[3] ?? 50000 );
$gate        = dirname( __DIR__ ) . '/early-gate.php';
$work        = sys_get_temp_dir() . '/ss-bench-' . getmypid();
@mkdir( "$work/www", 0777, true );
@mkdir( "$work/data", 0777, true );
file_put_contents( "$work/www/index.php", "<?php echo 'ok';\n" );

// Range file: "SSFEED1\0", counts (v4, v6), then sorted start/end pairs.
$write = static function ( string $path, array $v4 ): void {
	$out = "SSFEED1\0" . pack( 'NN', count( $v4 ), 0 );
	foreach ( $v4 as [ $a, $b ] ) {
		$out .= pack( 'N', $a ) . pack( 'N', $b );
	}
	file_put_contents( $path, $out );
};
$block = array();
for ( $i = 0; $i < $ranges; $i++ ) {
	$start   = ( 11 << 24 ) + $i * 256; // 11.0.0.0/24, 11.0.1.0/24, ...
	$block[] = array( $start, $start + 255 );
}
$allow = array( array( ( 10 << 24 ) + 1, ( 10 << 24 ) + 1 ) );

$snapshot = static function ( array $block ) use ( $work, $write, $allow ): void {
	$write( "$work/data/block.bin", $block );
	$write( "$work/data/allow.bin", $allow );
	$empty = array(
		4 => '',
		6 => '',
	);
	file_put_contents(
		"$work/data/gate.json",
		json_encode(
			array(
				'v'           => 2,
				'built'       => time(),
				'valid_until' => time() + 3600,
				'enabled'     => true,
				'status'      => 403,
				'page'        => 'Blocked %%IP%%',
				'reason_rule' => 'Blocked',
				'reason_feed' => 'Blocklist',
				'proxy'       => array(
					'mode'    => 'none',
					'header'  => '',
					'trusted' => $empty,
				),
				'server'      => $empty,
				'feeds'       => '',
				'log_max'     => 1048576,
				'block_file'  => "$work/data/block.bin",
				'allow_file'  => "$work/data/allow.bin",
			)
		)
	);
};

$serve = static function ( bool $with_gate ) use ( $work, $gate, $concurrency ) {
	$port = 18000 + random_int( 0, 999 );
	$cmd  = sprintf(
		'exec env SENTINEL_SHIELD_GATE_CONFIG=%s PHP_CLI_SERVER_WORKERS=%d %s %s -S 127.0.0.1:%d -t %s',
		escapeshellarg( "$work/data/gate.json" ),
		max( 2, $concurrency ),
		escapeshellarg( PHP_BINARY ),
		$with_gate ? '-d auto_prepend_file=' . escapeshellarg( $gate ) : '',
		$port,
		escapeshellarg( "$work/www" )
	);
	$proc = proc_open( $cmd, array( 1 => array( 'file', '/dev/null', 'w' ), 2 => array( 'file', '/dev/null', 'w' ) ), $pipes );
	for ( $i = 0; $i < 50; $i++ ) {
		usleep( 100000 );
		if ( @file_get_contents( "http://127.0.0.1:$port/" ) !== false || str_contains( (string) ( $http_response_header[0] ?? '' ), '403' ) ) {
			break;
		}
	}
	return array( $proc, $port );
};

$load = static function ( int $port ) use ( $requests, $concurrency ): array {
	$mh      = curl_multi_init();
	$active  = array();
	$started = 0;
	$done    = 0;
	$codes   = array();
	$add     = static function () use ( $mh, $port, &$active, &$started ): void {
		$ch = curl_init( "http://127.0.0.1:$port/" );
		curl_setopt( $ch, CURLOPT_RETURNTRANSFER, true );
		curl_multi_add_handle( $mh, $ch );
		$active[ (int) $ch ] = $ch;
		++$started;
	};
	$t0 = microtime( true );
	while ( $started < min( $concurrency, $requests ) ) {
		$add();
	}
	do {
		curl_multi_exec( $mh, $running );
		curl_multi_select( $mh, 0.05 );
		while ( $info = curl_multi_info_read( $mh ) ) {
			$ch                = $info['handle'];
			$code              = (int) curl_getinfo( $ch, CURLINFO_RESPONSE_CODE );
			$codes[ $code ]    = ( $codes[ $code ] ?? 0 ) + 1;
			curl_multi_remove_handle( $mh, $ch );
			unset( $active[ (int) $ch ] );
			++$done;
			if ( $started < $requests ) {
				$add();
			}
		}
	} while ( $done < $requests );
	$secs = microtime( true ) - $t0;
	curl_multi_close( $mh );
	ksort( $codes );
	return array( $requests / $secs, $codes );
};

$report = static function ( string $label, array $result, string $note = '' ): void {
	$codes = implode( ', ', array_map( static fn( $c, $n ) => $c . " x" . $n, array_keys( $result[1] ), $result[1] ) );
	printf( "  %-9s %8.0f req/s   (%s)%s\n", $label, $result[0], $codes, '' !== $note ? "  $note" : '' );
};

printf( "Early firewall benchmark: %d requests, concurrency %d, %d blocked ranges, PHP %s\n", $requests, $concurrency, $ranges, PHP_VERSION );
$snapshot( $block );

[ $proc, $port ] = $serve( false );
$report( 'baseline', $load( $port ) );
proc_terminate( $proc );
proc_close( $proc );

[ $proc, $port ] = $serve( true );
$report( 'pass', $load( $port ), 'visitor not listed: every request reads gate.json and searches both range files' );
proc_terminate( $proc );
proc_close( $proc );

// The visitor (127.0.0.1) is blocked: add it to the block list.
$snapshot( array_merge( $block, array( array( ( 127 << 24 ) + 1, ( 127 << 24 ) + 1 ) ) ) ); // Ranges must stay sorted.
[ $proc, $port ] = $serve( true );
$flood = $load( $port );
proc_terminate( $proc );
proc_close( $proc );
clearstatcache();
$log = "$work/data/early-blocks.log";
$report( 'flood', $flood, sprintf( 'blocked: %d log lines for %d blocks (sampled once the log passes 100 KB)', is_file( $log ) ? count( file( $log ) ) : 0, $requests ) );

array_map( 'unlink', glob( "$work/data/*" ) ?: array() );
array_map( 'unlink', glob( "$work/www/*" ) ?: array() );
@rmdir( "$work/data" );
@rmdir( "$work/www" );
@rmdir( $work );
