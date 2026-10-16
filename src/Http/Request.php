<?php
/**
 * Request accessors with sanitization for logging.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Http;

defined( 'ABSPATH' ) || exit;

/**
 * Read-only views of the current request.
 */
final class Request {

	/**
	 * Request URI with control characters removed, truncated to 2048 bytes.
	 */
	public static function uri(): string {
		$uri = isset( $_SERVER['REQUEST_URI'] ) ? (string) wp_unslash( $_SERVER['REQUEST_URI'] ) : '/'; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Sanitized below; esc_url_raw would alter attack payloads we need to log.
		return substr( (string) preg_replace( '/[\x00-\x1F\x7F]/', '', $uri ), 0, 2048 );
	}

	/**
	 * URI path only.
	 */
	public static function path(): string {
		$path = wp_parse_url( self::uri(), PHP_URL_PATH );
		return is_string( $path ) ? $path : '/';
	}

	/**
	 * Sanitized user agent, truncated to 512 characters.
	 */
	public static function user_agent(): string {
		$ua = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
		return substr( $ua, 0, 512 );
	}

	/**
	 * Upper-case HTTP method.
	 */
	public static function method(): string {
		$method = isset( $_SERVER['REQUEST_METHOD'] ) ? sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : 'get';
		return strtoupper( $method );
	}

	/**
	 * Selected raw proxy-related headers for the diagnostics screen.
	 *
	 * @return array<string, string>
	 */
	public static function proxy_headers(): array {
		$keys = array( 'REMOTE_ADDR', 'SERVER_ADDR', 'HTTP_X_FORWARDED_FOR', 'HTTP_CF_CONNECTING_IP', 'HTTP_X_REAL_IP', 'HTTP_TRUE_CLIENT_IP', 'HTTP_X_CLUSTER_CLIENT_IP', 'HTTP_FORWARDED', 'HTTP_CF_IPCOUNTRY', 'HTTP_X_FORWARDED_PROTO' );
		$out  = array();
		foreach ( $keys as $key ) {
			$out[ $key ] = isset( $_SERVER[ $key ] ) ? sanitize_text_field( wp_unslash( (string) $_SERVER[ $key ] ) ) : '';
		}
		return $out;
	}
}
