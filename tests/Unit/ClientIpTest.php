<?php
/**
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SentinelShield\Net\ClientIp;
use SentinelShield\Net\IpRangeSet;

final class ClientIpTest extends TestCase {

	/**
	 * @param array<string, string> $server  Server vars.
	 * @param list<string>          $trusted Trusted CIDRs.
	 */
	private static function resolve( array $server, string $mode, string $header, array $trusted ): string {
		return ( new ClientIp( $server, $mode, $header, IpRangeSet::from_strings( $trusted ) ) )->resolve();
	}

	public function test_mode_none_ignores_headers(): void {
		$server = array(
			'REMOTE_ADDR'          => '198.51.100.9',
			'HTTP_X_FORWARDED_FOR' => '1.2.3.4',
			'HTTP_CF_CONNECTING_IP' => '1.2.3.4',
		);
		$this->assertSame( '198.51.100.9', self::resolve( $server, 'none', '', array() ) );
	}

	public function test_untrusted_peer_cannot_spoof_header(): void {
		$server = array(
			'REMOTE_ADDR'           => '203.0.113.66',
			'HTTP_CF_CONNECTING_IP' => '1.1.1.1',
		);
		$this->assertSame( '203.0.113.66', self::resolve( $server, 'cloudflare', 'CF-Connecting-IP', array( '173.245.48.0/20' ) ) );
	}

	public function test_cloudflare_trusted_peer(): void {
		$server = array(
			'REMOTE_ADDR'           => '173.245.48.10',
			'HTTP_CF_CONNECTING_IP' => '198.51.100.23',
		);
		$this->assertSame( '198.51.100.23', self::resolve( $server, 'cloudflare', 'CF-Connecting-IP', array( '173.245.48.0/20' ) ) );
	}

	public function test_xff_rightmost_untrusted_hop_wins(): void {
		// Attacker prepends a fake IP; the LB appends the real client.
		$server = array(
			'REMOTE_ADDR'          => '10.0.0.2',
			'HTTP_X_FORWARDED_FOR' => '6.6.6.6, 198.51.100.23',
		);
		$this->assertSame( '198.51.100.23', self::resolve( $server, 'load_balancer', 'X-Forwarded-For', array( '10.0.0.0/8' ) ) );
	}

	public function test_xff_skips_multiple_trusted_hops(): void {
		$server = array(
			'REMOTE_ADDR'          => '10.0.0.2',
			'HTTP_X_FORWARDED_FOR' => '6.6.6.6, 198.51.100.23, 10.0.5.5, 10.0.0.3',
		);
		$this->assertSame( '198.51.100.23', self::resolve( $server, 'custom', 'X-Forwarded-For', array( '10.0.0.0/8' ) ) );
	}

	public function test_all_trusted_returns_leftmost(): void {
		$server = array(
			'REMOTE_ADDR'          => '10.0.0.2',
			'HTTP_X_FORWARDED_FOR' => '10.9.9.9, 10.0.0.3',
		);
		$this->assertSame( '10.9.9.9', self::resolve( $server, 'custom', 'X-Forwarded-For', array( '10.0.0.0/8' ) ) );
	}

	public function test_malformed_hop_falls_back_to_remote_addr(): void {
		$server = array(
			'REMOTE_ADDR'          => '10.0.0.2',
			'HTTP_X_FORWARDED_FOR' => '198.51.100.23, <script>',
		);
		$this->assertSame( '10.0.0.2', self::resolve( $server, 'custom', 'X-Forwarded-For', array( '10.0.0.0/8' ) ) );
	}

	public function test_empty_header_falls_back(): void {
		$this->assertSame( '10.0.0.2', self::resolve( array( 'REMOTE_ADDR' => '10.0.0.2' ), 'custom', 'X-Real-IP', array( '10.0.0.0/8' ) ) );
	}

	public function test_ipv6_chain_and_ports(): void {
		$server = array(
			'REMOTE_ADDR'          => '2001:db8:aaaa::1',
			'HTTP_X_FORWARDED_FOR' => '[2001:db8:1234::5]:51234',
		);
		$this->assertSame( '2001:db8:1234::5', self::resolve( $server, 'custom', 'X-Forwarded-For', array( '2001:db8:aaaa::/48' ) ) );
	}

	public function test_rfc7239_forwarded_header(): void {
		$server = array(
			'REMOTE_ADDR'    => '10.0.0.2',
			'HTTP_FORWARDED' => 'for=6.6.6.6;proto=https, for="[2001:db8::7]";proto=https',
		);
		$this->assertSame( '2001:db8::7', self::resolve( $server, 'custom', 'Forwarded', array( '10.0.0.0/8' ) ) );
	}

	public function test_invalid_remote_addr_yields_empty_string(): void {
		$this->assertSame( '', self::resolve( array( 'REMOTE_ADDR' => 'garbage' ), 'none', '', array() ) );
	}

	public function test_details_report_trust(): void {
		$details = ( new ClientIp(
			array(
				'REMOTE_ADDR'          => '10.0.0.2',
				'HTTP_X_FORWARDED_FOR' => '198.51.100.23',
			),
			'custom',
			'X-Forwarded-For',
			IpRangeSet::from_strings( array( '10.0.0.0/8' ) )
		) )->details();
		$this->assertTrue( $details['remote_trusted'] );
		$this->assertSame( 'X-Forwarded-For', $details['source'] );
		$this->assertSame( '10.0.0.2', $details['remote_addr'] );
	}

	/**
	 * Pentest D3: an unusable right-most hop falls back to the proxy and says so.
	 *
	 * @dataProvider unusable_headers
	 */
	public function test_unusable_header_is_flagged_as_fallback( string $value ): void {
		$server  = array(
			'REMOTE_ADDR'          => '10.0.0.5',
			'HTTP_X_FORWARDED_FOR' => $value,
		);
		$details = ( new ClientIp( $server, 'custom', 'X-Forwarded-For', IpRangeSet::from_strings( array( '10.0.0.0/8' ) ) ) )->details();
		$this->assertSame( '10.0.0.5', $details['ip'] );
		$this->assertTrue( $details['fallback'] );
	}

	/**
	 * @return array<string, array{0:string}>
	 */
	public static function unusable_headers(): array {
		return array(
			'unknown'       => array( 'unknown' ),
			'leading zeros' => array( '203.000.113.009' ),
			'decimal'       => array( '3405803785' ),
			'trailing junk' => array( '203.0.113.9, unknown' ),
			'only commas'   => array( ',' ),
		);
	}

	public function test_normal_resolution_is_not_fallback(): void {
		$trusted = IpRangeSet::from_strings( array( '10.0.0.0/8' ) );
		$ok      = ( new ClientIp( array( 'REMOTE_ADDR' => '10.0.0.5', 'HTTP_X_FORWARDED_FOR' => '198.51.100.7' ), 'custom', 'X-Forwarded-For', $trusted ) )->details();
		$untrusted = ( new ClientIp( array( 'REMOTE_ADDR' => '198.51.100.9' ), 'custom', 'X-Forwarded-For', $trusted ) )->details();
		$this->assertFalse( $ok['fallback'] );
		$this->assertSame( '198.51.100.7', $ok['ip'] );
		$this->assertFalse( $untrusted['fallback'], 'A direct visitor (untrusted peer) is identified by REMOTE_ADDR.' );
		$this->assertSame( '198.51.100.9', $untrusted['ip'] );
	}

	/**
	 * Review finding 1: a trusted proxy that does not say who the visitor is
	 * (missing, empty or proxy-only header) leaves the visitor unknown.
	 *
	 * @dataProvider unresolved_chains
	 *
	 * @param string $header Configured header.
	 * @param string $value  Header value (null = not sent).
	 * @param string $ip     Expected reported IP.
	 */
	public function test_unresolved_visitor_is_fallback( string $header, ?string $value, string $ip ): void {
		$server = array( 'REMOTE_ADDR' => '10.0.0.5' );
		if ( null !== $value ) {
			$server[ 'HTTP_' . strtoupper( str_replace( '-', '_', $header ) ) ] = $value;
		}
		$details = ( new ClientIp( $server, 'custom', $header, IpRangeSet::from_strings( array( '10.0.0.0/8', '192.0.2.0/24' ) ) ) )->details();
		$this->assertTrue( $details['fallback'] );
		$this->assertSame( $ip, $details['ip'] );
	}

	/**
	 * @return array<string, array{0:string, 1:?string, 2:string}>
	 */
	public static function unresolved_chains(): array {
		return array(
			'xff missing'        => array( 'X-Forwarded-For', null, '10.0.0.5' ),
			'xff empty'          => array( 'X-Forwarded-For', '', '10.0.0.5' ),
			'xff blank'          => array( 'X-Forwarded-For', '   ', '10.0.0.5' ),
			'xff only proxies'   => array( 'X-Forwarded-For', '192.0.2.4, 10.0.0.9', '192.0.2.4' ),
			'real ip missing'    => array( 'X-Real-IP', null, '10.0.0.5' ),
			'real ip is a proxy' => array( 'X-Real-IP', '10.0.0.9', '10.0.0.9' ),
			'fwd only proxies'   => array( 'Forwarded', 'for=192.0.2.4, for=10.0.0.9', '192.0.2.4' ),
			'fwd without for'    => array( 'Forwarded', 'proto=https;host=example.com', '10.0.0.5' ),
		);
	}
}
