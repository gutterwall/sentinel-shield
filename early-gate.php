<?php
/**
 * Sentinel Shield early firewall.
 *
 * Runs before WordPress, or before other plugins: blocks IPs on Sentinel
 * Shield's blocklist (manual rules, lockouts and blocklist feeds) without
 * loading WordPress, so a flood costs almost nothing and PHP files outside
 * WordPress are covered too.
 *
 * Load it in one of two ways (Settings → Server & CDN sets this up):
 * - auto_prepend_file = /path/to/wp-content/plugins/sentinel-shield/early-gate.php
 *   in php.ini, .user.ini, an Apache php_value line or nginx's PHP_VALUE, or
 * - the must-use plugin loader that Sentinel Shield can install.
 *
 * It only reads a snapshot that WordPress writes to its private folder
 * (sentinel-shield-data next to the WordPress folder, or SENTINEL_SHIELD_DATA_DIR). Whenever anything is unclear (no snapshot, a stale or damaged
 * one, protection switched off, the emergency file gate.disabled next to the
 * snapshot) it lets the request through to WordPress, whose own firewall then
 * decides. It never blocks more than WordPress would.
 *
 * Set the environment variable SENTINEL_SHIELD_GATE_CONFIG to the snapshot's
 * path (shown on the Server & CDN tab) when the folder is somewhere else.
 *
 * @package SentinelShield
 */

// phpcs:disable WordPress.Security.ValidatedSanitizedInput, WordPress.WP.AlternativeFunctions, WordPress.PHP.DiscouragedPHPFunctions, WordPress.PHP.NoSilencedErrors, WordPress.Security.EscapeOutput, WordPress.DateTime.RestrictedFunctions, WordPress.Security.NonceVerification -- Runs before WordPress (only checks whether unlock parameters are present): no WordPress functions exist yet; every value is validated or escaped here.

if ( defined( 'SENTINEL_SHIELD_EARLY_GATE' ) || PHP_SAPI === 'cli' ) {
	return;
}
if ( ! defined( 'ABSPATH' ) ) {
	// Without WordPress this file only works as auto_prepend_file. Requested
	// over the web as a page of its own, it does nothing.
	if ( isset( $_SERVER['SCRIPT_FILENAME'] ) && realpath( (string) $_SERVER['SCRIPT_FILENAME'] ) === realpath( __FILE__ ) ) {
		exit;
	}
}
define( 'SENTINEL_SHIELD_EARLY_GATE', defined( 'ABSPATH' ) ? 'mu' : 'prepend' );

$sentinel_shield_gate_path = isset( $GLOBALS['sentinel_shield_gate_config'] ) && is_string( $GLOBALS['sentinel_shield_gate_config'] ) ? $GLOBALS['sentinel_shield_gate_config'] : (string) getenv( 'SENTINEL_SHIELD_GATE_CONFIG' );
if ( '' === $sentinel_shield_gate_path ) {
	// The private folder next to the WordPress folder (plugins/sentinel-shield is four levels below it).
	$sentinel_shield_gate_path = dirname( __DIR__, 4 ) . '/sentinel-shield-data/gate.json';
}

( static function ( string $path ): void {
	if ( ! is_file( $path ) || is_file( dirname( $path ) . '/gate.disabled' ) ) {
		return;
	}
	$config = json_decode( (string) @file_get_contents( $path ), true );
	if ( ! is_array( $config ) || 2 !== ( $config['v'] ?? 0 ) || empty( $config['enabled'] ) || (int) ( $config['valid_until'] ?? 0 ) < time() ) {
		return;
	}

	// Requests WordPress must see even from a blocked IP: unlock links and the unlock form.
	if ( isset( $_GET['sentinel_unlock'] ) || isset( $_GET['sentinel_unlock_form'] ) || isset( $_POST['sentinel_unlock_request'] ) ) {
		return;
	}

	$packed   = static function ( $data ): array {
		$out = array(
			4 => '',
			6 => '',
		);
		foreach ( array(
			4 => 8,
			6 => 32,
		) as $version => $width ) {
			$raw             = is_array( $data ) ? base64_decode( (string) ( $data[ $version ] ?? '' ), true ) : false;
			$out[ $version ] = ( false !== $raw && 0 === strlen( $raw ) % $width ) ? $raw : '';
		}
		return $out;
	};
	$contains = static function ( array $set, string $bin ): bool {
		$len = strlen( $bin );
		if ( 4 !== $len && 16 !== $len ) {
			return false;
		}
		$data  = $set[ 4 === $len ? 4 : 6 ];
		$width = 2 * $len;
		$lo    = 0;
		$hi    = intdiv( strlen( $data ), $width ) - 1;
		while ( $lo <= $hi ) {
			$mid = ( $lo + $hi ) >> 1;
			if ( strcmp( $bin, substr( $data, $mid * $width, $len ) ) < 0 ) {
				$hi = $mid - 1;
			} elseif ( strcmp( $bin, substr( $data, $mid * $width + $len, $len ) ) > 0 ) {
				$lo = $mid + 1;
			} else {
				return true;
			}
		}
		return false;
	};
	// Binary search in a compiled range file (16-byte header, then sorted ranges).
	$in_file = static function ( string $file, string $bin ): ?bool {
		$h = '' !== $file && is_file( $file ) ? @fopen( $file, 'rb' ) : false;
		if ( false === $h ) {
			return null;
		}
		$found = false;
		$head  = (string) fread( $h, 16 );
		if ( 16 !== strlen( $head ) || "SSFEED1\0" !== substr( $head, 0, 8 ) ) {
			fclose( $h );
			return null;
		}
		$n     = (array) unpack( 'Nv4/Nv6', substr( $head, 8 ) );
		$len   = strlen( $bin );
		$width = 2 * $len;
		$base  = 16 + ( 16 === $len ? (int) $n['v4'] * 8 : 0 );
		$lo    = 0;
		$hi    = ( 4 === $len ? (int) $n['v4'] : (int) $n['v6'] ) - 1;
		while ( $lo <= $hi ) {
			$mid = ( $lo + $hi ) >> 1;
			fseek( $h, $base + $mid * $width );
			$row = (string) fread( $h, $width );
			if ( strlen( $row ) !== $width ) {
				break;
			}
			if ( strcmp( $bin, substr( $row, 0, $len ) ) < 0 ) {
				$hi = $mid - 1;
			} elseif ( strcmp( $bin, substr( $row, $len, $len ) ) > 0 ) {
				$lo = $mid + 1;
			} else {
				$found = true;
				break;
			}
		}
		fclose( $h );
		return $found;
	};
	$to_bin  = static function ( string $ip ): ?string {
		$ip = trim( $ip, " \t[]\"" );
		if ( preg_match( '/^(\d{1,3}(?:\.\d{1,3}){3}):\d+$/', $ip, $m ) ) {
			$ip = $m[1];
		}
		if ( false === filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return null;
		}
		$bin = inet_pton( $ip );
		return false === $bin ? null : $bin;
	};

	// Client IP, as Sentinel Shield works it out (see ClientIp).
	$remote = $to_bin( (string) ( $_SERVER['REMOTE_ADDR'] ?? '' ) );
	if ( null === $remote ) {
		return;
	}
	$proxy    = (array) ( $config['proxy'] ?? array() );
	$trusted  = $packed( $proxy['trusted'] ?? null );
	$client   = $remote;
	$fallback = false;
	$header   = (string) ( $proxy['header'] ?? '' );
	if ( '' !== $header && 'none' !== ( $proxy['mode'] ?? 'none' ) && $contains( $trusted, $remote ) ) {
		$key   = 'HTTP_' . strtoupper( str_replace( '-', '_', $header ) );
		$value = isset( $_SERVER[ $key ] ) && is_string( $_SERVER[ $key ] ) ? trim( $_SERVER[ $key ] ) : '';
		$hops  = array();
		if ( 'forwarded' === strtolower( $header ) ) {
			foreach ( explode( ',', $value ) as $element ) {
				foreach ( explode( ';', $element ) as $pair ) {
					$parts = explode( '=', trim( $pair ), 2 );
					if ( 2 === count( $parts ) && 'for' === strtolower( trim( $parts[0] ) ) ) {
						$hops[] = trim( $parts[1], " \t\"" );
					}
				}
			}
		} else {
			$hops = array_map( 'trim', explode( ',', $value ) );
		}
		$hops     = array_values( array_filter( $hops, static fn( string $h ): bool => '' !== $h ) );
		$fallback = true;
		for ( $i = count( $hops ) - 1; $i >= 0; $i-- ) {
			$bin = $to_bin( $hops[ $i ] );
			if ( null === $bin ) {
				break; // Malformed: the visitor is unknown.
			}
			if ( ! $contains( $trusted, $bin ) ) {
				$client   = $bin;
				$fallback = false;
				break;
			}
		}
	}

	$server = $packed( $config['server'] ?? null );
	$uri    = (string) ( $_SERVER['REQUEST_URI'] ?? '/' );
	if ( $contains( $server, $client ) && 'wp-cron.php' === basename( (string) parse_url( $uri, PHP_URL_PATH ) ) ) {
		return;
	}
	// A request that fell back to a proxy's own address gets no allowlist privileges.
	if ( ! $fallback && true === $in_file( (string) ( $config['allow_file'] ?? '' ), $client ) ) {
		return;
	}
	$reason = '';
	if ( true === $in_file( (string) ( $config['block_file'] ?? '' ), $client ) ) {
		$reason = (string) ( $config['reason_rule'] ?? 'Blocked' );
	} elseif ( ! $contains( $server, $client ) && true === $in_file( (string) ( $config['feeds'] ?? '' ), $client ) ) {
		$reason = (string) ( $config['reason_feed'] ?? 'Blocklist' );
	}
	if ( '' === $reason ) {
		return;
	}

	$ip = (string) inet_ntop( $client );
	// Note the block for WordPress's event log (imported hourly). The path is
	// logged without its query string (which can carry tokens). During a flood
	// only one block in ten is written (with a weight), and the file is capped.
	$log  = dirname( $path ) . '/early-blocks.log';
	$size = is_file( $log ) ? (int) filesize( $log ) : 0;
	$rate = $size > 102400 ? 10 : 1;
	if ( $size < (int) ( $config['log_max'] ?? 1048576 ) && ( 1 === $rate || 0 === mt_rand( 0, $rate - 1 ) ) ) {
		$line = json_encode(
			array(
				't'  => time(),
				'ip' => $ip,
				'u'  => substr( (string) strtok( $uri, '?' ), 0, 255 ),
				'a'  => substr( (string) ( $_SERVER['HTTP_USER_AGENT'] ?? '' ), 0, 255 ),
				'r'  => $reason,
				's'  => $rate,
			)
		);
		@file_put_contents( $log, $line . "\n", FILE_APPEND | LOCK_EX );
	}

	$code = 404 === (int) ( $config['status'] ?? 403 ) ? 404 : 403;
	if ( ! headers_sent() ) {
		http_response_code( $code );
		header( 'Content-Type: text/html; charset=utf-8' );
		header( 'Cache-Control: no-store, no-cache, must-revalidate, max-age=0' );
		header( 'X-Robots-Tag: noindex, nofollow' );
		header( 'X-Content-Type-Options: nosniff' );
		header( 'X-Sentinel-Shield-Gate: early' );
	}
	$esc = static fn( string $s ): string => htmlspecialchars( $s, ENT_QUOTES, 'UTF-8' );
	echo str_replace( array( '%%IP%%', '%%REASON%%', '%%TIME%%' ), array( $esc( $ip ), $esc( $reason ), $esc( gmdate( 'Y-m-d H:i:s' ) ) ), (string) ( $config['page'] ?? 'Access denied' ) );
	exit;
} )( $sentinel_shield_gate_path );
unset( $sentinel_shield_gate_path );
