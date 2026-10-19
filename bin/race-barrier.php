<?php
/**
 * Test-only must-use plugin for bin/race-test.php (never shipped, never left
 * installed): a request with the header "X-Race-Barrier: <name>/<count>"
 * waits here until <count> such requests with the same name have arrived, so
 * they all continue into WordPress at the same moment.
 *
 * @package SentinelShield
 */

// phpcs:disable -- Developer tool, not shipped in the plugin zip.

if ( isset( $_SERVER['HTTP_X_RACE_BARRIER'] ) && preg_match( '#^([a-z0-9-]{1,40})/(\d{1,3})$#', (string) $_SERVER['HTTP_X_RACE_BARRIER'], $sentinel_shield_race ) ) {
	( static function ( string $name, int $count ): void {
		$file   = sys_get_temp_dir() . '/sentinel-shield-race-' . $name;
		$handle = fopen( $file, 'c+' );
		flock( $handle, LOCK_EX );
		$arrived = (int) stream_get_contents( $handle ) + 1;
		ftruncate( $handle, 0 );
		rewind( $handle );
		fwrite( $handle, (string) $arrived );
		fflush( $handle );
		flock( $handle, LOCK_UN );
		fclose( $handle );
		$deadline = microtime( true ) + 15;
		while ( (int) @file_get_contents( $file ) < $count && microtime( true ) < $deadline ) {
			usleep( 1000 );
		}
		header( 'X-Race-Arrived: ' . $arrived );
	} )( $sentinel_shield_race[1], (int) $sentinel_shield_race[2] );
	unset( $sentinel_shield_race );
}
