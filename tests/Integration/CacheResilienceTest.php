<?php
/**
 * Enforcement with an evicted, stale or unavailable cache.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Tests\Integration;

use SentinelShield\Firewall\Gate;
use SentinelShield\Firewall\RuleCache;
use SentinelShield\Net\Cidr;
use SentinelShield\Plugin;
use SentinelShield\Repository\BlockRepository;

/**
 * Review 5 (P1). Runs with whatever cache the suite has: transients without a
 * persistent object cache, Redis in the object-cache CI job. Whatever the
 * cache loses or keeps too long, the database decides: a block needs a rule
 * that exists, and a missing cache only costs speed.
 */
final class CacheResilienceTest extends \WP_UnitTestCase {

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

	private function blocked( string $ip ): bool {
		return $this->gate->evaluate( $ip, '/', false, true )->is_block();
	}

	/**
	 * A restart or eviction loses everything cached (the request's own memo
	 * included, as in a new request).
	 */
	private function evict(): void {
		wp_cache_flush();
		global $wpdb;
		$like = $wpdb->esc_like( '_site_transient_sentinel_shield_' ) . '%';
		$wpdb->query( $wpdb->prepare( 'DELETE FROM %i WHERE option_name LIKE %s OR option_name LIKE %s', $wpdb->options, $like, $wpdb->esc_like( '_site_transient_timeout_sentinel_shield_' ) . '%' ) );
		if ( is_multisite() ) {
			$wpdb->query( $wpdb->prepare( 'DELETE FROM %i WHERE meta_key LIKE %s OR meta_key LIKE %s', $wpdb->sitemeta, $like, $wpdb->esc_like( '_site_transient_timeout_sentinel_shield_' ) . '%' ) );
		}
		( new \ReflectionProperty( RuleCache::class, 'memo' ) )->setValue( $this->cache, array() );
	}

	public function test_eviction_changes_nothing(): void {
		$id = $this->repo->add( 'block', Cidr::parse( '203.0.113.0/24' ), 'cache', 'manual' );
		$this->repo->add( 'allow', Cidr::parse( '203.0.113.7' ), 'cache', 'manual' );
		$this->cache->flush();
		$this->assertTrue( $this->blocked( '203.0.113.9' ) );
		$this->evict();
		$this->assertTrue( $this->blocked( '203.0.113.9' ), 'still blocked after the cache was emptied' );
		$this->assertFalse( $this->blocked( '203.0.113.7' ), 'the allowlist still wins' );
		$this->repo->delete( $id );
		$this->cache->flush();
		$this->evict();
		$this->assertFalse( $this->blocked( '203.0.113.9' ), 'and an unblock holds after eviction too' );
	}

	public function test_a_stale_block_list_never_blocks_without_a_rule(): void {
		$id = $this->repo->add( 'block', Cidr::parse( '198.51.100.20' ), 'cache', 'manual' );
		$this->cache->flush();
		$this->assertTrue( $this->blocked( '198.51.100.20' ) );
		// Deleted behind the cache's back (another server, a database restore): the cached list still has it.
		global $wpdb;
		$wpdb->delete( $this->repo->table(), array( 'id' => $id ) );
		( new \ReflectionProperty( RuleCache::class, 'memo' ) )->setValue( $this->cache, array() );
		$this->assertTrue( $this->cache->get( 'block' )->contains( (string) inet_pton( '198.51.100.20' ) ), 'the cache is stale' );
		$decision = $this->gate->evaluate( '198.51.100.20', '/', false, true );
		$this->assertFalse( $decision->is_block(), 'no rule, no block' );
		$this->assertSame( 'stale_cache', $decision->reason );
		$this->assertFalse( $this->cache->get( 'block' )->contains( (string) inet_pton( '198.51.100.20' ) ), 'and the cache healed itself' );
	}

	public function test_a_cache_that_never_answers_only_costs_speed(): void {
		$this->repo->add( 'block', Cidr::parse( '192.0.2.0/24' ), 'cache', 'manual' );
		$this->cache->flush();
		// Every read misses: an unreachable Redis, or transients that cannot be stored.
		$miss = static fn() => false;
		foreach ( array( 'rules_block', 'rules_allow', 'rules_allow_login', 'feed_set' ) as $key ) {
			add_filter( 'site_transient_sentinel_shield_' . $key, $miss );
		}
		add_filter( 'pre_wp_cache_get', $miss );
		try {
			for ( $i = 0; $i < 3; $i++ ) {
				( new \ReflectionProperty( RuleCache::class, 'memo' ) )->setValue( $this->cache, array() );
				$this->assertTrue( $this->blocked( '192.0.2.5' ), "request $i" );
				$this->assertFalse( $this->blocked( '192.0.3.5' ), "request $i" );
			}
		} finally {
			foreach ( array( 'rules_block', 'rules_allow', 'rules_allow_login', 'feed_set' ) as $key ) {
				remove_filter( 'site_transient_sentinel_shield_' . $key, $miss );
			}
			remove_filter( 'pre_wp_cache_get', $miss );
		}
	}

	public function test_an_expiring_rule_ends_on_time_whatever_was_cached(): void {
		$this->repo->add( 'block', Cidr::parse( '198.51.100.30' ), 'cache', 'lockout', time() + 3600 );
		$this->cache->flush();
		$this->assertTrue( $this->blocked( '198.51.100.30' ) );
		global $wpdb;
		$wpdb->query( $wpdb->prepare( 'UPDATE %i SET expires_at = %s', $this->repo->table(), gmdate( 'Y-m-d H:i:s', time() - 1 ) ) );
		( new \ReflectionProperty( RuleCache::class, 'memo' ) )->setValue( $this->cache, array() );
		$this->assertFalse( $this->blocked( '198.51.100.30' ), 'expired in the database: not blocked, though the cached list still had it' );
	}
}
