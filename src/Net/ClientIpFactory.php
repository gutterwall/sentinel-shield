<?php
/**
 * Builds a ClientIp resolver from the trusted proxy settings.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Net;

use SentinelShield\Settings;

defined( 'ABSPATH' ) || exit;

/**
 * Maps the proxy preset to trusted ranges and the header to read.
 */
final class ClientIpFactory {

	/**
	 * Used for the load balancer preset when no CIDRs are entered.
	 */
	public const PRIVATE_RANGES = array( '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8', '100.64.0.0/10', '::1/128', 'fc00::/7' );

	/**
	 * Constructor.
	 *
	 * @param Settings         $settings   Settings.
	 * @param CloudflareRanges $cloudflare Cloudflare range provider.
	 */
	public function __construct( private Settings $settings, private CloudflareRanges $cloudflare ) {}

	/**
	 * Resolver for the current request.
	 */
	public function from_globals(): ClientIp {
		return $this->create( $_SERVER ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- Every value is validated as an IP by ClientIp.
	}

	/**
	 * Resolver for arbitrary server vars (used by the simulator and tests).
	 *
	 * @param array<string, mixed>      $server Server vars.
	 * @param array<string, mixed>|null $proxy  Proxy settings override.
	 */
	public function create( array $server, ?array $proxy = null ): ClientIp {
		$config = $this->config( $proxy );
		return new ClientIp( $server, $config['mode'], $config['header'], IpRangeSet::from_strings( $config['cidrs'] ) );
	}

	/**
	 * The effective proxy configuration: preset, header and trusted ranges.
	 *
	 * @param array<string, mixed>|null $proxy proxy.* settings (default: saved ones).
	 * @return array{mode:string, header:string, cidrs:list<string>}
	 */
	public function config( ?array $proxy = null ): array {
		$proxy  = $proxy ?? (array) $this->settings->get( 'proxy', array() );
		$mode   = (string) ( $proxy['mode'] ?? 'none' );
		$lines  = IpRangeSet::parse_lines( (string) ( $proxy['trusted_cidrs'] ?? '' ) );
		$header = (string) ( $proxy['header'] ?? 'X-Forwarded-For' );

		switch ( $mode ) {
			case 'cloudflare':
				$cidrs  = array_merge( $this->cloudflare->all(), $lines );
				$header = 'CF-Connecting-IP';
				break;
			case 'load_balancer':
				$cidrs = $lines ? $lines : self::PRIVATE_RANGES;
				break;
			case 'custom':
				$cidrs = $lines;
				break;
			default:
				$mode   = 'none';
				$cidrs  = array();
				$header = '';
		}
		return array(
			'mode'   => $mode,
			'header' => $header,
			'cidrs'  => array_values( $cidrs ),
		);
	}
}
