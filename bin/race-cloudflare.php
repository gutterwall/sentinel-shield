<?php
/**
 * Test-only must-use plugin for bin/race-test.php (never shipped, never left
 * installed): when SENTINEL_SHIELD_RACE_CF names a folder, Cloudflare's list
 * API is answered from that folder instead of the network, and every request
 * is logged with its start and end time (calls.log), so the race test can
 * tell whether two workers changed the list at the same time. An upload takes
 * 0.4 s, which leaves room for overlaps to show. With
 * SENTINEL_SHIELD_RACE_CF_BARRIER=<count>, each process waits at init until
 * <count> processes have arrived, so they all start syncing at once.
 *
 * @package SentinelShield
 */

// phpcs:disable -- Developer tool, not shipped in the plugin zip.

$sentinel_shield_race_cf = (string) getenv( 'SENTINEL_SHIELD_RACE_CF' );
if ( '' !== $sentinel_shield_race_cf && is_dir( $sentinel_shield_race_cf ) ) {
	( static function ( string $dir ): void {
		$count = (int) getenv( 'SENTINEL_SHIELD_RACE_CF_BARRIER' );
		if ( $count > 1 ) {
			add_action(
				'init',
				static function () use ( $dir, $count ): void {
					$file   = $dir . '/barrier';
					$handle = fopen( $file, 'c+' );
					flock( $handle, LOCK_EX );
					$arrived = (int) stream_get_contents( $handle ) + 1;
					ftruncate( $handle, 0 );
					rewind( $handle );
					fwrite( $handle, (string) $arrived );
					fflush( $handle );
					flock( $handle, LOCK_UN );
					fclose( $handle );
					$deadline = microtime( true ) + 30;
					while ( (int) @file_get_contents( $file ) < $count && microtime( true ) < $deadline ) {
						usleep( 1000 );
					}
				},
				0
			);
		}
		add_filter(
			'pre_http_request',
			static function ( $pre, $args, $url ) use ( $dir ) {
				if ( ! str_starts_with( (string) $url, 'https://api.cloudflare.com/' ) ) {
					return $pre;
				}
				$start  = microtime( true );
				$method = (string) ( $args['method'] ?? 'GET' );
				$reply  = static fn( array $body ): array => array(
					'headers'  => array(),
					'body'     => (string) json_encode( $body ),
					'response' => array( 'code' => 200, 'message' => 'OK' ),
					'cookies'  => array(),
					'filename' => null,
				);
				if ( preg_match( '#/bulk_operations/[^/]+$#', (string) $url ) ) {
					$result = $reply( array( 'success' => true, 'result' => array( 'status' => 'completed' ) ) );
				} elseif ( 'PUT' === $method ) {
					usleep( 400000 );
					$items = array_column( (array) json_decode( (string) ( $args['body'] ?? '' ), true ), 'ip' );
					file_put_contents( $dir . '/list.json', (string) json_encode( $items ), LOCK_EX );
					$result = $reply( array( 'success' => true, 'result' => array( 'operation_id' => 'op-' . getmypid() . '-' . bin2hex( random_bytes( 3 ) ) ) ) );
				} else {
					$result = $reply( array( 'success' => true, 'result' => array( 'kind' => 'ip', 'name' => 'race', 'num_items' => 0 ) ) );
				}
				file_put_contents( $dir . '/calls.log', json_encode( array( $method, (string) $url, getmypid(), $start, microtime( true ) ) ) . "\n", FILE_APPEND | LOCK_EX );
				return $result;
			},
			10,
			3
		);
	} )( $sentinel_shield_race_cf );
}
unset( $sentinel_shield_race_cf );
