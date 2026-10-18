<?php
/**
 * Lockout safety: emergency bypass, CLI and server-cron exemptions.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Safety;

use SentinelShield\Net\IpAddress;
use SentinelShield\Net\IpRangeSet;
use SentinelShield\Settings;

defined( 'ABSPATH' ) || exit;

/**
 * Decides which requests can never be blocked.
 */
final class SafetyGuard {

	/**
	 * Lazily built server address set.
	 *
	 * @var IpRangeSet|null
	 */
	private ?IpRangeSet $server_set = null;

	/**
	 * Constructor.
	 *
	 * @param Settings             $settings Settings.
	 * @param array<string, mixed> $server   $_SERVER-style array.
	 */
	public function __construct( private Settings $settings, private array $server ) {}

	/**
	 * Defining SENTINEL_SHIELD_DISABLE as true in wp-config.php disables all blocking.
	 */
	public static function emergency_disabled(): bool {
		return defined( 'SENTINEL_SHIELD_DISABLE' ) && SENTINEL_SHIELD_DISABLE;
	}

	/**
	 * WP-CLI or any command-line PHP (e.g. a system cron running wp-cron.php).
	 */
	public function is_cli(): bool {
		return ( defined( 'WP_CLI' ) && WP_CLI ) || 'cli' === PHP_SAPI;
	}

	/**
	 * Whether enforcement is bypassed for this request.
	 */
	public function is_bypassed(): bool {
		return self::emergency_disabled() || $this->is_cli();
	}

	/**
	 * Loopback, SERVER_ADDR, LOCAL_ADDR and admin-configured server IPs.
	 */
	public function server_ranges(): IpRangeSet {
		if ( null === $this->server_set ) {
			$items = array( '127.0.0.0/8', '::1' );
			foreach ( array( 'SERVER_ADDR', 'LOCAL_ADDR' ) as $key ) {
				if ( ! empty( $this->server[ $key ] ) && is_string( $this->server[ $key ] ) ) {
					$items[] = $this->server[ $key ];
				}
			}
			$items            = array_merge( $items, IpRangeSet::parse_lines( (string) $this->settings->get( 'proxy.server_ips', '' ) ) );
			$this->server_set = IpRangeSet::from_strings( $items );
		}
		return $this->server_set;
	}

	/**
	 * Whether a packed IP belongs to this server.
	 *
	 * @param string $bin Packed IP.
	 */
	public function is_server_ip( string $bin ): bool {
		return $this->server_ranges()->contains( $bin );
	}

	/**
	 * Whether the URI targets wp-cron.php (or WordPress says this is a cron run).
	 *
	 * @param string $uri Request URI.
	 */
	public function is_cron_path( string $uri ): bool {
		$path = wp_parse_url( $uri, PHP_URL_PATH );
		return ( is_string( $path ) && 'wp-cron.php' === basename( $path ) ) || ( defined( 'DOING_CRON' ) && DOING_CRON );
	}

	/**
	 * Never block wp-cron.php requested by this server.
	 *
	 * @param string $bin Packed client IP.
	 * @param string $uri Request URI.
	 */
	public function is_server_cron( string $bin, string $uri ): bool {
		return $this->is_cron_path( $uri ) && $this->is_server_ip( $bin );
	}

	/**
	 * Human-readable warnings about the IP detection setup.
	 *
	 * @param array<string, mixed> $details ClientIp::details().
	 * @return list<string>
	 */
	public function detection_warnings( array $details ): array {
		$warnings = array();
		$remote   = IpAddress::to_binary( (string) $details['remote_addr'] );
		$mode     = (string) $this->settings->get( 'proxy.mode', 'none' );
		$has_fwd  = '' !== (string) ( $this->server['HTTP_X_FORWARDED_FOR'] ?? '' ) || '' !== (string) ( $this->server['HTTP_CF_CONNECTING_IP'] ?? '' ) || '' !== (string) ( $this->server['HTTP_X_REAL_IP'] ?? '' );

		if ( null === $remote ) {
			$warnings[] = __( 'REMOTE_ADDR is missing or invalid. Blocking cannot work reliably until this is fixed in the web server configuration.', 'sentinel-shield' );
			return $warnings;
		}
		if ( 'none' === $mode && $has_fwd ) {
			$warnings[] = __( 'Forwarding headers are present but Trusted Proxy is "None". If your site is behind a CDN or load balancer, every visitor may appear to have the same IP. Choose the matching preset.', 'sentinel-shield' );
		}
		if ( 'none' === $mode && IpAddress::is_private( $remote ) ) {
			$warnings[] = __( 'REMOTE_ADDR is a private or loopback address. This usually means a reverse proxy sits in front of PHP. Configure a trusted proxy, or blocking one visitor may block everyone.', 'sentinel-shield' );
		}
		if ( 'none' !== $mode && empty( $details['remote_trusted'] ) ) {
			$warnings[] = __( 'Your current request did not come from a trusted proxy, so the forwarding header was ignored. If the site really is behind that proxy, its IP ranges are missing from the trusted list.', 'sentinel-shield' );
		}
		if ( 'none' !== $mode && ! empty( $details['remote_trusted'] ) && '' === (string) $details['header_value'] ) {
			/* translators: %s: header name. */
			$warnings[] = sprintf( __( 'The request came from a trusted proxy but the %s header was empty. Check the header name. Until it is fixed, such requests are treated as anonymous: they share the proxy\'s address and get none of its allowlist or server exemptions.', 'sentinel-shield' ), (string) $details['header'] );
		} elseif ( ! empty( $details['fallback'] ) ) {
			/* translators: %s: header name. */
			$warnings[] = sprintf( __( 'The %s header did not name a visitor (it is malformed or lists only trusted proxies), so this request is treated as anonymous: it shares the proxy\'s address and gets none of its allowlist or server exemptions. Check that every proxy in the chain is trusted and appends the client address.', 'sentinel-shield' ), (string) $details['header'] );
		}
		if ( self::emergency_disabled() ) {
			$warnings[] = __( 'SENTINEL_SHIELD_DISABLE is set in wp-config.php: all blocking is disabled.', 'sentinel-shield' );
		}
		return $warnings;
	}
}
