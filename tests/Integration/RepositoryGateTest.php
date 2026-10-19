<?php
/**
 * Integration tests against a real database (WordPress test suite).
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Tests\Integration;

use SentinelShield\Firewall\Gate;
use SentinelShield\Firewall\RuleCache;
use SentinelShield\Lockout\Unblocker;
use SentinelShield\Net\Cidr;
use SentinelShield\Net\IpAddress;
use SentinelShield\Plugin;
use SentinelShield\Repository\BlockRepository;
use SentinelShield\Repository\TokenRepository;

final class RepositoryGateTest extends \WP_UnitTestCase {

	private BlockRepository $repo;
	private RuleCache $cache;
	private Gate $gate;

	public function set_up(): void {
		parent::set_up();
		$c           = Plugin::instance()->container();
		$this->repo  = $c->get( BlockRepository::class );
		$this->cache = $c->get( RuleCache::class );
		$this->gate  = $c->get( Gate::class );
		global $wpdb;
		$wpdb->query( $wpdb->prepare( 'DELETE FROM %i', $this->repo->table() ) );
		$this->cache->flush();
	}

	public function test_binary_storage_round_trip_ipv4_and_ipv6(): void {
		$this->repo->add( 'block', Cidr::parse( '198.51.100.0/24' ), 'v4', 'manual' );
		$this->repo->add( 'block', Cidr::parse( '2001:db8::/32' ), 'v6', 'manual' );
		$this->assertCount( 1, $this->repo->find_containing( 'block', (string) IpAddress::to_binary( '198.51.100.200' ) ) );
		$this->assertCount( 1, $this->repo->find_containing( 'block', (string) IpAddress::to_binary( '2001:db8:ffff::1' ) ) );
		$this->assertCount( 0, $this->repo->find_containing( 'block', (string) IpAddress::to_binary( '198.51.101.1' ) ) );
	}

	public function test_duplicate_rule_merges_and_keeps_permanent(): void {
		$cidr = Cidr::parse( '203.0.113.5' );
		$id1  = $this->repo->add( 'block', $cidr, 'first', 'manual', null );
		$id2  = $this->repo->add( 'block', $cidr, 'second', 'lockout_login', time() + 60 );
		$this->assertSame( $id1, $id2 );
		$this->assertNull( $this->repo->get( $id1 )['expires_at'] );
	}

	public function test_expired_rules_do_not_match(): void {
		global $wpdb;
		$id = $this->repo->add( 'block', Cidr::parse( '203.0.113.6' ), 'x', 'manual', time() + 3600 );
		$wpdb->update( $this->repo->table(), array( 'expires_at' => gmdate( 'Y-m-d H:i:s', time() - 10 ) ), array( 'id' => $id ) );
		$this->cache->flush();
		$this->assertFalse( $this->gate->evaluate( '203.0.113.6', '/', false, true )->is_block() );
		$this->assertSame( 1, $this->repo->purge_expired() );
	}

	public function test_allowlist_beats_blocklist(): void {
		$this->repo->add( 'block', Cidr::parse( '198.51.100.0/24' ), 'range', 'manual' );
		$this->repo->add( 'allow', Cidr::parse( '198.51.100.10' ), 'admin', 'manual' );
		$this->cache->flush();
		$this->assertSame( 'allow', $this->gate->evaluate( '198.51.100.10', '/', false, true )->action );
		$this->assertSame( 'block', $this->gate->evaluate( '198.51.100.11', '/', false, true )->action );
		$this->assertSame( 'block', $this->gate->evaluate( '198.51.100.10', '/', true, true )->action );
	}

	public function test_server_cron_is_exempt(): void {
		$this->repo->add( 'block', Cidr::parse( '127.0.0.1' ), 'x', 'manual' );
		$this->cache->flush();
		$this->assertSame( 'server_cron', $this->gate->evaluate( '127.0.0.1', '/wp-cron.php?doing_wp_cron=1', false, true )->reason );
		$this->assertTrue( $this->gate->evaluate( '127.0.0.1', '/', false, true )->is_block() );
	}

	public function test_cli_bypass_without_simulation(): void {
		$this->repo->add( 'block', Cidr::parse( '203.0.113.9' ), 'x', 'manual' );
		$this->cache->flush();
		$this->assertSame( 'bypass', $this->gate->evaluate( '203.0.113.9' )->reason, 'PHPUnit runs under the CLI SAPI, which is always bypassed.' );
	}

	public function test_unblocker_keeps_ranges_unless_asked(): void {
		$this->repo->add( 'block', Cidr::parse( '203.0.113.20' ), 'single', 'lockout_login' );
		$this->repo->add( 'block', Cidr::parse( '203.0.113.0/24' ), 'range', 'manual' );
		$unblocker = Plugin::instance()->container()->get( Unblocker::class );
		$result    = $unblocker->unblock( '203.0.113.20', false, 1, 0, 'test' );
		$this->assertSame( 1, $result['removed'] );
		$this->assertSame( array( '203.0.113.0/24' ), $result['ranges'] );
		$this->assertSame( 'allow', $this->gate->evaluate( '203.0.113.20', '/', false, true )->action );
	}

	public function test_unlock_tokens_are_single_use(): void {
		$tokens = Plugin::instance()->container()->get( TokenRepository::class );
		$token  = $tokens->create( 1, '203.0.113.30', 600 );
		$this->assertNotNull( $tokens->consume( $token ) );
		$this->assertNull( $tokens->consume( $token ) );
		$this->assertNull( $tokens->consume( str_repeat( 'a', 64 ) ) );
		// Used a while ago (a second consume in the same second could look unchanged to MySQL).
		global $wpdb;
		$wpdb->query( $wpdb->prepare( 'UPDATE %i SET used_at = %s', $tokens->table(), gmdate( 'Y-m-d H:i:s', time() - 60 ) ) );
		$this->assertNull( $tokens->consume( $token ), 'still used' );
		$this->assertNull( $tokens->peek( $token ) );
	}

	/**
	 * Review 5 (mutation testing): the rule lookup used by the admin screens
	 * and the IP check skips expired rules unless asked for them.
	 */
	public function test_rule_lookup_skips_expired_rules(): void {
		global $wpdb;
		$id = $this->repo->add( 'block', Cidr::parse( '203.0.113.0/24' ), 'x', 'manual', time() + 3600 );
		$this->assertCount( 1, $this->repo->find_containing( 'block', (string) inet_pton( '203.0.113.9' ) ) );
		$wpdb->update( $this->repo->table(), array( 'expires_at' => gmdate( 'Y-m-d H:i:s', time() - 1 ) ), array( 'id' => $id ) );
		$this->assertSame( array(), $this->repo->find_containing( 'block', (string) inet_pton( '203.0.113.9' ) ) );
		$this->assertCount( 1, $this->repo->find_containing( 'block', (string) inet_pton( '203.0.113.9' ), false ) );
	}

	/**
	 * An unlock link stops working when it expires, used or not.
	 */
	public function test_unlock_tokens_expire(): void {
		global $wpdb;
		$tokens = Plugin::instance()->container()->get( TokenRepository::class );
		$token  = $tokens->create( 1, '203.0.113.30', 600 );
		$this->assertNotNull( $tokens->peek( $token ) );
		$wpdb->query( $wpdb->prepare( 'UPDATE %i SET expires_at = %s', $tokens->table(), gmdate( 'Y-m-d H:i:s', time() - 1 ) ) );
		$this->assertNull( $tokens->peek( $token ) );
		$this->assertNull( $tokens->consume( $token ) );
	}

	/**
	 * The unlock form answers at most the configured number of requests per
	 * IP and hour; the next one is refused without looking anything up.
	 */
	public function test_unlock_requests_are_limited_per_ip(): void {
		$service = Plugin::instance()->container()->get( \SentinelShield\Unlock\UnlockService::class );
		$ask     = new \ReflectionMethod( $service, 'request_locked' );
		$ask->setAccessible( true );
		delete_site_transient( 'sentinel_shield_unlock_rl_' . md5( '203.0.113.31' ) );
		for ( $i = 0; $i < 3; $i++ ) {
			$this->assertSame( 'generic', $ask->invoke( $service, '203.0.113.31', 'nobody@example.org', 'generic' )['message'] );
		}
		$this->assertStringContainsString( 'Too many', $ask->invoke( $service, '203.0.113.31', 'nobody@example.org', 'generic' )['message'] );
		$this->assertSame( 'generic', $ask->invoke( $service, '203.0.113.32', 'nobody@example.org', 'generic' )['message'], 'per IP' );
	}

	/**
	 * Application passwords expire at their maximum age and retire when unused.
	 */
	public function test_application_password_age_limits(): void {
		$settings = Plugin::instance()->container()->get( \SentinelShield\Settings::class );
		update_site_option(
			\SentinelShield\Settings::OPTION,
			array(
				'login' => array(
					'app_password_max_days'    => 30,
					'app_password_unused_days' => 10,
				),
			)
		);
		$settings->refresh();
		$now    = 1800000000;
		$status = static fn( int $created, int $used ): string => \SentinelShield\Login\AppPasswordPolicy::status(
			array(
				'created'   => $created,
				'last_used' => $used,
			),
			$settings,
			$now
		);
		try {
			$this->assertSame( 'ok', $status( $now - 29 * DAY_IN_SECONDS, $now - 9 * DAY_IN_SECONDS ) );
			$this->assertSame( 'expired', $status( $now - 31 * DAY_IN_SECONDS, $now ) );
			$this->assertSame( 'unused', $status( $now - 20 * DAY_IN_SECONDS, $now - 11 * DAY_IN_SECONDS ) );
			$this->assertSame( 'unused', $status( $now - 11 * DAY_IN_SECONDS, 0 ), 'never used: counted from its creation' );
		} finally {
			delete_site_option( \SentinelShield\Settings::OPTION );
			$settings->refresh();
		}
	}
}
