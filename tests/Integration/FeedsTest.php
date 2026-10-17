<?php
/**
 * Blocklist feeds end to end: download (mocked HTTP), storage, cache and Gate.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Tests\Integration;

use SentinelShield\Feeds\FeedCatalog;
use SentinelShield\Feeds\FeedUpdater;
use SentinelShield\Firewall\Gate;
use SentinelShield\Firewall\RuleCache;
use SentinelShield\Net\Cidr;
use SentinelShield\Plugin;
use SentinelShield\Repository\BlockRepository;
use SentinelShield\Repository\FeedRepository;
use SentinelShield\Settings;

final class FeedsTest extends \WP_UnitTestCase {

	private const ET_URL  = 'https://rules.emergingthreats.net/blockrules/compromised-ips.txt';
	private const TOR_URL = 'https://check.torproject.org/torbulkexitlist';

	private Settings $settings;
	private FeedUpdater $updater;
	private Gate $gate;
	private RuleCache $cache;

	/**
	 * Mocked responses keyed by URL: [code, body, headers].
	 *
	 * @var array<string, array{0:int, 1:string, 2?:array<string, string>}>
	 */
	private array $responses = array();

	/**
	 * Requests made: [url, args].
	 *
	 * @var list<array{0:string, 1:array<string, mixed>}>
	 */
	private array $requests = array();

	public function set_up(): void {
		parent::set_up();
		$c              = Plugin::instance()->container();
		$this->settings = $c->get( Settings::class );
		$this->updater  = $c->get( FeedUpdater::class );
		$this->gate     = $c->get( Gate::class );
		$this->cache    = $c->get( RuleCache::class );
		global $wpdb;
		$wpdb->query( $wpdb->prepare( 'DELETE FROM %i', $c->get( FeedRepository::class )->table() ) );
		$wpdb->query( $wpdb->prepare( 'DELETE FROM %i', $c->get( BlockRepository::class )->table() ) );
		delete_site_option( FeedUpdater::STATE_OPTION );
		$this->cache->flush();
		$this->cache->flush_feeds();
		$this->responses = array();
		$this->requests  = array();
		add_filter( 'pre_http_request', array( $this, 'mock_http' ), 10, 3 );
	}

	public function tear_down(): void {
		remove_filter( 'pre_http_request', array( $this, 'mock_http' ), 10 );
		$this->configure( array() );
		parent::tear_down();
	}

	/**
	 * @param mixed                $pre  Short-circuit value.
	 * @param array<string, mixed> $args Request args.
	 * @param string               $url  URL.
	 * @return array<string, mixed>|\WP_Error
	 */
	public function mock_http( mixed $pre, array $args, string $url ): array|\WP_Error {
		unset( $pre );
		$this->requests[] = array( $url, $args );
		if ( ! isset( $this->responses[ $url ] ) ) {
			return new \WP_Error( 'http_request_failed', 'No mock for ' . $url );
		}
		[ $code, $body ] = $this->responses[ $url ];
		return array(
			'headers'  => $this->responses[ $url ][2] ?? array(),
			'body'     => $body,
			'response' => array(
				'code'    => $code,
				'message' => '',
			),
			'cookies'  => array(),
			'filename' => null,
		);
	}

	/**
	 * Enables exactly these feeds (plus any other setting overrides).
	 *
	 * @param list<string>         $lists Feed slugs.
	 * @param array<string, mixed> $extra Settings overrides.
	 */
	private function configure( array $lists, array $extra = array() ): void {
		$all = $this->settings->network_settings();
		foreach ( array_keys( FeedCatalog::NAMES ) as $slug ) {
			$all['feeds']['lists'][ $slug ] = in_array( $slug, $lists, true );
		}
		$all['modules']['feeds']['test_mode'] = 'inherit';
		$this->settings->save_network( array_replace_recursive( $all, $extra ) );
	}

	/**
	 * A plain list body with $n public IPs plus the given extra lines.
	 *
	 * @param int          $n     Filler count.
	 * @param list<string> $extra Extra lines.
	 */
	private static function body( int $n, array $extra ): string {
		$lines = array( '# test list' );
		for ( $i = 1; $i <= $n; $i++ ) {
			$lines[] = '45.1.' . intdiv( $i, 250 ) . '.' . ( $i % 250 + 1 );
		}
		return implode( "\n", array_merge( $lines, $extra ) ) . "\n";
	}

	private function blocks( string $ip ): bool {
		return $this->gate->evaluate( $ip, '/', false, true )->is_block();
	}

	public function test_enabled_feed_blocks_listed_ip_only(): void {
		$this->configure( array( 'et_compromised' ) );
		$this->responses[ self::ET_URL ] = array( 200, self::body( 60, array( '91.92.93.94', '185.10.20.0/24' ) ) );

		$this->assertTrue( $this->updater->update( 'et_compromised' ) );
		$decision = $this->gate->evaluate( '185.10.20.77', '/', false, true );
		$this->assertTrue( $decision->is_block() );
		$this->assertSame( 'feed', $decision->rule['source'] );
		$this->assertStringContainsString( 'Emerging Threats', $decision->reason );
		$this->assertTrue( $this->blocks( '91.92.93.94' ) );
		$this->assertFalse( $this->blocks( '91.92.93.95' ) );
		$this->assertSame( 62, (int) $this->updater->state()['et_compromised']['count'] );
	}

	public function test_feeds_are_additive_and_disabling_one_keeps_the_other(): void {
		$this->configure( array( 'et_compromised', 'tor_exits' ) );
		$this->responses[ self::ET_URL ]  = array( 200, self::body( 60, array( '91.92.93.94', '91.92.93.1' ) ) );
		$this->responses[ self::TOR_URL ] = array( 200, self::body( 110, array( '91.92.93.94', '77.77.77.77' ) ) );
		$this->assertTrue( $this->updater->update( 'et_compromised' ) );
		$this->assertTrue( $this->updater->update( 'tor_exits' ) );

		$both = $this->gate->evaluate( '91.92.93.94', '/', false, true );
		$this->assertSame( array( 'et_compromised', 'tor_exits' ), $both->rule['feeds'] );
		$this->assertTrue( $this->blocks( '91.92.93.1' ) );
		$this->assertTrue( $this->blocks( '77.77.77.77' ) );

		// Turning off Emerging Threats removes only its rows.
		$this->configure( array( 'tor_exits' ) );
		$this->assertTrue( $this->blocks( '91.92.93.94' ), 'Still listed by the Tor feed.' );
		$this->assertFalse( $this->blocks( '91.92.93.1' ), 'Only Emerging Threats listed it.' );
		$this->assertTrue( $this->blocks( '77.77.77.77' ) );
		$this->assertArrayNotHasKey( 'et_compromised', Plugin::instance()->container()->get( FeedRepository::class )->counts() );
	}

	public function test_allowlist_wins_over_feeds(): void {
		$this->configure( array( 'et_compromised' ) );
		$this->responses[ self::ET_URL ] = array( 200, self::body( 60, array( '185.10.20.0/24' ) ) );
		$this->updater->update( 'et_compromised' );
		Plugin::instance()->container()->get( BlockRepository::class )->add( 'allow', Cidr::parse( '185.10.20.5' ), 'office', 'manual' );
		$this->cache->flush();
		$this->assertFalse( $this->blocks( '185.10.20.5' ) );
		$this->assertTrue( $this->blocks( '185.10.20.6' ) );
	}

	public function test_manual_rules_are_untouched_by_feeds(): void {
		$repo = Plugin::instance()->container()->get( BlockRepository::class );
		$id   = $repo->add( 'block', Cidr::parse( '91.92.93.94' ), 'my rule', 'manual' );
		$this->configure( array( 'et_compromised' ) );
		$this->responses[ self::ET_URL ] = array( 200, self::body( 60, array( '91.92.93.94' ) ) );
		$this->updater->update( 'et_compromised' );
		$this->configure( array() );
		$this->cache->flush();
		$this->assertSame( 'manual', $repo->get( $id )['source'] );
		$this->assertTrue( $this->blocks( '91.92.93.94' ), 'Manual rule still blocks after the feed is turned off.' );
	}

	public function test_reserved_ranges_from_a_feed_are_never_stored(): void {
		$this->configure( array( 'et_compromised' ) );
		$this->responses[ self::ET_URL ] = array( 200, self::body( 60, array( '10.0.0.0/8', '127.0.0.0/8', '192.168.0.0/16' ) ) );
		$this->updater->update( 'et_compromised' );
		$this->assertFalse( $this->blocks( '10.1.2.3' ) );
		$this->assertFalse( $this->blocks( '127.0.0.1' ) );
		$this->assertFalse( $this->blocks( '192.168.1.1' ) );
		$this->assertSame( 3, (int) $this->updater->state()['et_compromised']['skipped'] );
	}

	public function test_broken_download_keeps_previous_copy_and_backs_off(): void {
		$this->configure( array( 'et_compromised' ) );
		$this->responses[ self::ET_URL ] = array( 200, self::body( 60, array( '91.92.93.94' ) ) );
		$this->updater->update( 'et_compromised' );

		$this->responses[ self::ET_URL ] = array( 200, "<html>maintenance</html>\n1.2.3.4\n" );
		$result                          = $this->updater->update( 'et_compromised', true );
		$this->assertWPError( $result );
		$this->assertTrue( $this->blocks( '91.92.93.94' ), 'Previous copy still enforced.' );
		$state = $this->updater->state()['et_compromised'];
		$this->assertSame( 1, $state['failures'] );
		$this->assertSame( 61, (int) $state['count'] );
		$this->assertGreaterThanOrEqual( time() + HOUR_IN_SECONDS - 5, $state['next_due'] );
	}

	public function test_rate_limit_respects_retry_after(): void {
		$this->configure( array( 'et_compromised' ) );
		$this->responses[ self::ET_URL ] = array( 429, 'slow down', array( 'retry-after' => '20000' ) );
		$this->assertWPError( $this->updater->update( 'et_compromised' ) );
		$this->assertGreaterThanOrEqual( time() + 19990, $this->updater->state()['et_compromised']['next_due'] );
		$this->assertSame( array(), $this->updater->due() );
	}

	public function test_conditional_requests_and_neutral_user_agent(): void {
		$this->configure( array( 'et_compromised' ) );
		$this->responses[ self::ET_URL ] = array( 200, self::body( 60, array() ), array( 'etag' => '"v1"' ) );
		$this->updater->update( 'et_compromised' );
		$args = $this->requests[0][1];
		$this->assertStringStartsWith( 'SentinelShield/', $args['user-agent'] );
		$this->assertStringNotContainsString( home_url(), $args['user-agent'] );

		$this->responses[ self::ET_URL ] = array( 304, '' );
		$this->assertTrue( $this->updater->update( 'et_compromised' ) );
		$this->assertSame( '"v1"', $this->requests[1][1]['headers']['If-None-Match'] );
		$this->assertTrue( $this->blocks( '45.1.0.2' ), 'Unchanged list stays enforced.' );
	}

	public function test_schedule_honours_interval_and_provider_minimum(): void {
		$this->configure( array( 'et_compromised', 'ipsum_3' ), array( 'feeds' => array( 'update_hours' => '12' ) ) );
		$this->assertSame( 12 * HOUR_IN_SECONDS, $this->updater->interval( 'et_compromised' ) );
		$this->assertSame( 24 * HOUR_IN_SECONDS, $this->updater->interval( 'ipsum_3' ), 'IPsum is rebuilt daily, so never fetched more often.' );
		$this->assertSame( array( 'et_compromised', 'ipsum_3' ), $this->updater->due() );

		$this->responses[ self::ET_URL ] = array( 200, self::body( 60, array() ) );
		$this->updater->update( 'et_compromised' );
		$next = $this->updater->state()['et_compromised']['next_due'];
		$this->assertGreaterThanOrEqual( time() + 12 * HOUR_IN_SECONDS - 5, $next );
		$this->assertLessThanOrEqual( time() + 12 * HOUR_IN_SECONDS + 30 * MINUTE_IN_SECONDS, $next );
		$this->assertSame( array( 'ipsum_3' ), $this->updater->due() );
	}

	public function test_feed_test_mode_override(): void {
		$this->configure( array( 'et_compromised' ), array( 'general' => array( 'test_mode' => false ) ) );
		$this->assertFalse( $this->gate->is_test_for_source( 'feed' ) );
		$this->configure( array( 'et_compromised' ), array( 'general' => array( 'test_mode' => false ) ) );
		$all                                  = $this->settings->network_settings();
		$all['modules']['feeds']['test_mode'] = 'on';
		$this->settings->save_network( $all );
		$this->assertTrue( $this->gate->is_test_for_source( 'feed' ), 'Feeds can be trialled in log-only mode.' );
		$this->assertFalse( $this->gate->is_test_for_source( 'manual' ), 'Manual rules stay enforced.' );
	}

	public function test_module_off_disables_matching(): void {
		$this->configure( array( 'et_compromised' ) );
		$this->responses[ self::ET_URL ] = array( 200, self::body( 60, array( '91.92.93.94' ) ) );
		$this->updater->update( 'et_compromised' );
		$this->configure( array( 'et_compromised' ), array( 'modules' => array( 'feeds' => array( 'enabled' => false ) ) ) );
		$this->assertFalse( $this->blocks( '91.92.93.94' ) );
	}
}
