<?php
/**
 * Recognizes outbound requests to public blockchain RPC gateways.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Lockdown;

defined( 'ABSPATH' ) || exit;

/**
 * The SC malware (and the related "EtherHiding" campaigns) read their commands
 * from a smart contract through any of about twenty public Ethereum/BSC RPC
 * gateways, so blocking one host leaves the others. Requests are therefore
 * matched both by gateway host and by their JSON-RPC body (eth_call and friends),
 * which also catches gateways not on the list.
 *
 * Only requests made through the WordPress HTTP API can be stopped this way;
 * code calling curl directly bypasses it, which is why the scanner also looks for
 * blockchain calls in code.
 */
final class OutboundGuard {

	/**
	 * Gateway hosts; an entry matches the host itself and its subdomains.
	 */
	public const HOSTS = array(
		'cloudflare-eth.com',
		'llamarpc.com',
		'rpc.ankr.com',
		'publicnode.com',
		'drpc.org',
		'rpc.flashbots.net',
		'1rpc.io',
		'merkle.io',
		'infura.io',
		'g.alchemy.com',
		'mevblocker.io',
		'blastapi.io',
		'securerpc.com',
		'meowrpc.com',
		'omniatech.io',
		'nodies.app',
		'gateway.tenderly.co',
		'gateway.fm',
		'blockpi.network',
		'blxrbdn.com',
		'payload.de',
		'getblock.io',
		'quiknode.pro',
		'p2pify.com',
		'nodereal.io',
		'onfinality.io',
		'zan.top',
		'unifra.io',
		'lavanet.xyz',
		'builder0x69.io',
		'bnbchain.org',
		'defibit.io',
		'ninicoin.io',
		'polygon-rpc.com',
		'etherscan.io',
		'bscscan.com',
	);

	/**
	 * Why a request looks like blockchain RPC traffic, or null.
	 *
	 * @param string               $url  Request URL.
	 * @param array<string, mixed> $args WP_Http arguments.
	 */
	public static function match( string $url, array $args = array() ): ?string {
		$host = strtolower( (string) wp_parse_url( $url, PHP_URL_HOST ) );
		if ( '' !== $host ) {
			/**
			 * Hosts that may be contacted even though they look like blockchain gateways
			 * (for example by a legitimate crypto payments plugin).
			 *
			 * @param list<string> $hosts Host names.
			 */
			$allowed = (array) apply_filters( 'sentinel_shield_allowed_chain_hosts', array() );
			if ( in_array( $host, array_map( 'strtolower', $allowed ), true ) ) {
				return null;
			}
			foreach ( self::HOSTS as $gateway ) {
				if ( $host === $gateway || str_ends_with( $host, '.' . $gateway ) ) {
					return 'gateway ' . $gateway;
				}
			}
			// Binance Smart Chain seed nodes: bsc-dataseed1.binance.org etc.
			if ( str_starts_with( $host, 'bsc-dataseed' ) || str_starts_with( $host, 'data-seed-prebsc' ) ) {
				return 'gateway ' . $host;
			}
		}
		$body = $args['body'] ?? '';
		$body = is_string( $body ) ? $body : (string) wp_json_encode( $body );
		$text = substr( $body, 0, 65536 ) . ' ' . (string) wp_parse_url( $url, PHP_URL_QUERY );
		if ( preg_match( '/"method"\s*:\s*"((?:eth|net|web3|bsc|trace|debug)_[A-Za-z]+)"/', $text, $m ) || preg_match( '/(?:^|[?&\s])method=((?:eth|net|web3)_[A-Za-z]+)/', $text, $m ) ) {
			return 'JSON-RPC ' . $m[1];
		}
		return null;
	}
}
