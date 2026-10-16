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
	}
}
