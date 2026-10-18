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
 * It only reads a snapshot that WordPress writes (uploads/sentinel-shield/
 * gate.json). Whenever anything is unclear (no snapshot, a stale or damaged
 * one, protection switched off, the emergency file gate.disabled next to the
 * snapshot) it lets the request through to WordPress, whose own firewall then
 * decides. It never blocks more than WordPress would.
 *
 * Set the environment variable SENTINEL_SHIELD_GATE_CONFIG to the snapshot's
 * path if the uploads folder is not wp-content/uploads.
 *
 * @package SentinelShield
 */

// phpcs:disable WordPress.Security.ValidatedSanitizedInput, WordPress.WP.AlternativeFunctions, WordPress.PHP.DiscouragedPHPFunctions, WordPress.PHP.NoSilencedErrors, WordPress.Security.EscapeOutput, WordPress.DateTime.RestrictedFunctions, WordPress.Security.NonceVerification -- Runs before WordPress (only checks whether unlock parameters are present): no WordPress functions exist yet; every value is validated or escaped here.

if ( defined( 'SENTINEL_SHIELD_EARLY_GATE' ) || PHP_SAPI === 'cli' ) {
	return;
}
define( 'SENTINEL_SHIELD_EARLY_GATE', defined( 'ABSPATH' ) ? 'mu' : 'prepend' );

( static function (): void {
	global $sentinel_shield_gate_config;
	$path = isset( $sentinel_shield_gate_config ) && is_string( $sentinel_shield_gate_config ) ? $sentinel_shield_gate_config : (string) getenv( 'SENTINEL_SHIELD_GATE_CONFIG' );
	if ( '' === $path ) {
		$path = dirname( __DIR__, 2 ) . '/uploads/sentinel-shield/gate.json';
	}
	if ( ! is_file( $path ) || is_file( dirname( $path ) . '/gate.disabled' ) ) {
		return;
	}
	$config = json_decode( (string) @file_get_contents( $path ), true );
	if ( ! is_array( $config ) || 1 !== ( $config['v'] ?? 0 ) || empty( $config['enabled'] ) || (int) ( $config['valid_until'] ?? 0 ) < time() ) {
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
	$to_bin   = static function ( string $ip ): ?string {
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
	if ( ! $fallback && $contains( $packed( $config['allow'] ?? null ), $client ) ) {
		return;
	}
	$reason = '';
	if ( $contains( $packed( $config['block'] ?? null ), $client ) ) {
		$reason = (string) ( $config['reason_rule'] ?? 'Blocked' );
	} elseif ( '' !== (string) ( $config['feeds'] ?? '' ) && ! $contains( $server, $client ) ) {
		$file = (string) $config['feeds'];
		$h    = is_file( $file ) ? @fopen( $file, 'rb' ) : false;
		if ( false !== $h ) {
			$head = (string) fread( $h, 16 );
			if ( 16 === strlen( $head ) && "SSFEED1\0" === substr( $head, 0, 8 ) ) {
				$n     = (array) unpack( 'Nv4/Nv6', substr( $head, 8 ) );
				$len   = strlen( $client );
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
					if ( strcmp( $client, substr( $row, 0, $len ) ) < 0 ) {
						$hi = $mid - 1;
					} elseif ( strcmp( $client, substr( $row, $len, $len ) ) > 0 ) {
						$lo = $mid + 1;
					} else {
						$reason = (string) ( $config['reason_feed'] ?? 'Blocklist' );
						break;
					}
				}
			}
			fclose( $h );
		}
	}
	if ( '' === $reason ) {
		return;
	}

	$ip = (string) inet_ntop( $client );
	// Note the block for WordPress's event log (imported hourly); the file is capped.
	$log = dirname( $path ) . '/early-blocks.log';
	if ( ! is_file( $log ) || filesize( $log ) < (int) ( $config['log_max'] ?? 1048576 ) ) {
		$line = json_encode(
			array(
				't'  => time(),
				'ip' => $ip,
				'u'  => substr( $uri, 0, 255 ),
				'a'  => substr( (string) ( $_SERVER['HTTP_USER_AGENT'] ?? '' ), 0, 255 ),
				'r'  => $reason,
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
} )();
