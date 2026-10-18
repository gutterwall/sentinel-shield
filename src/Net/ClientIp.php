<?php
/**
 * Spoof-resistant client IP resolution.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Net;

defined( 'ABSPATH' ) || exit;

/**
 * Resolves the client IP from REMOTE_ADDR, consulting a forwarding header only
 * when the direct peer (REMOTE_ADDR) is a trusted proxy.
 *
 * For multi-hop headers (X-Forwarded-For, Forwarded) the chain is walked from the
 * right, skipping trusted proxies; the first untrusted hop is the client. Entries
 * to its left are attacker-controlled and ignored.
 */
final class ClientIp {

	/**
	 * Constructor.
	 *
	 * @param array<string, mixed> $server  $_SERVER-style array.
	 * @param string               $mode    none|cloudflare|load_balancer|custom.
	 * @param string               $header  Header name, e.g. "X-Forwarded-For".
	 * @param IpRangeSet           $trusted Trusted proxy ranges.
	 */
	public function __construct(
		private array $server,
		private string $mode,
		private string $header,
		private IpRangeSet $trusted
	) {}

	/**
	 * The resolved client IP in canonical text, or '' when REMOTE_ADDR is unusable.
	 */
	public function resolve(): string {
		return $this->details()['ip'];
	}

	/**
	 * Resolution details for diagnostics.
	 *
	 * "fallback" is true whenever the direct peer is a trusted proxy but no visitor
	 * address could be found: the forwarding header is missing, empty, unusable
	 * ("unknown", malformed) or lists only trusted proxies. "ip" is then a proxy's
	 * own address, shared by everyone who reaches the site that way, so such
	 * requests must not inherit the proxy's allowlist or server exemptions.
	 *
	 * @return array{ip:string, remote_addr:string, remote_trusted:bool, mode:string, header:string, header_value:string, source:string, fallback:bool}
	 */
	public function details(): array {
		$remote = IpAddress::normalize( (string) ( $this->server['REMOTE_ADDR'] ?? '' ) ) ?? '';
		$result = array(
			'ip'             => $remote,
			'remote_addr'    => $remote,
			'remote_trusted' => false,
			'mode'           => $this->mode,
			'header'         => $this->header,
			'header_value'   => '',
			'source'         => 'REMOTE_ADDR',
			'fallback'       => false,
		);
		if ( '' === $remote || 'none' === $this->mode || '' === $this->header ) {
			return $result;
		}
		$remote_bin               = (string) IpAddress::to_binary( $remote );
		$result['remote_trusted'] = $this->trusted->contains( $remote_bin );
		$value                    = self::header_value( $this->server, $this->header );
		$result['header_value']   = $value;
		if ( ! $result['remote_trusted'] ) {
			return $result;
		}
		if ( '' === $value ) {
			$result['fallback'] = true;
			return $result;
		}
		$hops = 'forwarded' === strtolower( $this->header ) ? self::parse_forwarded( $value ) : array_map( 'trim', explode( ',', $value ) );
		$hops = array_values( array_filter( $hops, static fn( string $h ): bool => '' !== $h ) );

		$leftmost = null;
		for ( $i = count( $hops ) - 1; $i >= 0; $i-- ) {
			$bin = IpAddress::to_binary( $hops[ $i ] );
			if ( null === $bin ) {
				// Malformed chain: do not guess, fall back to the direct peer.
				$result['fallback'] = true;
				return $result;
			}
			if ( ! $this->trusted->contains( $bin ) ) {
				$result['ip']     = (string) IpAddress::from_binary( $bin );
				$result['source'] = $this->header;
				return $result;
			}
			$leftmost = $bin;
		}
		// No hops, or every hop is a trusted proxy: the visitor is unknown. The
		// leftmost proxy is reported (it is where the request entered), but as a
		// fallback, so it gets no privileges.
		$result['fallback'] = true;
		if ( null !== $leftmost ) {
			$result['ip']     = (string) IpAddress::from_binary( $leftmost );
			$result['source'] = $this->header;
		}
		return $result;
	}

	/**
	 * Reads a header from a $_SERVER-style array.
	 *
	 * @param array<string, mixed> $server Server vars.
	 * @param string               $header Header name.
	 */
	public static function header_value( array $server, string $header ): string {
		$key = 'HTTP_' . strtoupper( str_replace( '-', '_', $header ) );
		return isset( $server[ $key ] ) && is_string( $server[ $key ] ) ? trim( $server[ $key ] ) : '';
	}

	/**
	 * Extracts for= values from an RFC 7239 Forwarded header.
	 *
	 * @param string $value Header value.
	 * @return list<string>
	 */
	private static function parse_forwarded( string $value ): array {
		$out = array();
		foreach ( explode( ',', $value ) as $element ) {
			foreach ( explode( ';', $element ) as $pair ) {
				$parts = explode( '=', trim( $pair ), 2 );
				if ( 2 === count( $parts ) && 'for' === strtolower( trim( $parts[0] ) ) ) {
					$out[] = trim( $parts[1], " \t\"" );
				}
			}
		}
		return $out;
	}
}
