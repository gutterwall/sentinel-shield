<?php
/**
 * Work kept off the hot path: feed snapshots, buffered hit counts, cached rule
 * matches, batched deletes and bounded fingerprints.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Tests\Integration;

use SentinelShield\Firewall\FeedSnapshot;
use SentinelShield\Firewall\Gate;
use SentinelShield\Firewall\RuleCache;
use SentinelShield\Lockdown\IntegrityScanner;
use SentinelShield\Net\Cidr;
use SentinelShield\Net\IpRangeSet;
use SentinelShield\Net\PackedRangeSet;
use SentinelShield\Plugin;
use SentinelShield\Repository\BlockRepository;
use SentinelShield\Repository\EventRepository;
use SentinelShield\Repository\FeedRepository;
use SentinelShield\Support\Batch;

final class PerformanceTest extends \WP_UnitTestCase {

	/**
	 * Files created by a test.
	 *
	 * @var list<string>
	 */
	private array $files = array();

	private bool $ext_cache = false;

	public function set_up(): void {
		parent::set_up();
		$this->ext_cache = (bool) wp_using_ext_object_cache();
	}

	public function tear_down(): void {
		foreach ( $this->files as $file ) {
			FeedSnapshot::close( $file );
			if ( is_file( $file ) ) {
				wp_delete_file( $file );
			}
		}
		wp_using_ext_object_cache( $this->ext_cache );
		FeedSnapshot::delete_all();
		Plugin::instance()->container()->get( RuleCache::class )->flush_feeds();
		parent::tear_down();
	}

	/**
	 * A set of IPv4 and IPv6 ranges.
	 */
	private static function sample_set(): IpRangeSet {
		$pairs = array();
		foreach ( array( '203.0.113.0/26', '198.51.100.7', '192.0.2.128/25', '100.64.0.0/10', '2001:db8::/48', '2001:db8:ffff::1' ) as $cidr ) {
			$c       = Cidr::parse( $cidr );
			$pairs[] = array( $c->start, $c->end );
		}
		for ( $i = 0; $i < 500; $i++ ) {
			$c       = Cidr::parse( '10.' . intdiv( $i, 250 ) . '.' . ( $i % 250 ) . '.0/28' );
			$pairs[] = array( $c->start, $c->end );
		}
		return IpRangeSet::from_pairs( $pairs );
	}

	public function test_feed_snapshot_answers_like_the_in_memory_set(): void {
		$set    = self::sample_set();
		$packed = PackedRangeSet::from_set( $set );
		$path   = FeedSnapshot::path( array( 'perf_test' ) );
		$this->files[] = $path;
		$this->assertTrue( FeedSnapshot::write( $set, $path ) );
		$snap = new FeedSnapshot( $path );
		$this->assertTrue( $snap->valid() );
		$this->assertSame( $packed->count(), $snap->count() );

		$probes = array( '203.0.113.0', '203.0.113.63', '203.0.113.64', '198.51.100.7', '198.51.100.8', '100.127.255.255', '100.128.0.0', '10.1.249.15', '10.1.249.16', '2001:db8::1', '2001:db8:1::', '2001:db8:ffff::1', '2001:db8:ffff::2', '::1', '0.0.0.0', '255.255.255.255' );
		for ( $i = 0; $i < 300; $i++ ) {
			$probes[] = wp_rand( 0, 255 ) . '.' . wp_rand( 0, 255 ) . '.' . wp_rand( 0, 255 ) . '.' . wp_rand( 0, 255 );
		}
		foreach ( $probes as $ip ) {
			$bin = (string) inet_pton( $ip );
			$this->assertSame( $packed->contains( $bin ), $snap->contains( $bin ), $ip );
		}

		// A damaged file is not used.
		file_put_contents( $path, substr( (string) file_get_contents( $path ), 0, -5 ) );
		FeedSnapshot::close( $path );
		$this->assertFalse( ( new FeedSnapshot( $path ) )->valid() );
	}

	public function test_rule_cache_compiles_one_snapshot_and_falls_back_to_the_database_meanwhile(): void {
		$c     = Plugin::instance()->container();
		$feeds = $c->get( FeedRepository::class );
		$cache = $c->get( RuleCache::class );
		global $wpdb;
		$wpdb->query( $wpdb->prepare( 'DELETE FROM %i', $feeds->table() ) );
		// Inserted directly: replace() commits its own transaction, which would end the test's.
		$range = Cidr::parse( '203.0.113.0/24' );
		$wpdb->query( $wpdb->prepare( 'INSERT INTO %i (feed, ip_version, ip_start, ip_end, prefix) VALUES (%s, 4, UNHEX(%s), UNHEX(%s), 24)', $feeds->table(), 'spamhaus_drop', bin2hex( $range->start ), bin2hex( $range->end ) ) );
		$cache->flush_feeds();

		// Another worker is compiling: this request asks the database instead.
		$other = new \wpdb( DB_USER, DB_PASSWORD, DB_NAME, DB_HOST );
		$name  = new \ReflectionMethod( \SentinelShield\Support\Mutex::class, 'db_name' );
		$name->setAccessible( true );
		$other->get_var( $other->prepare( 'SELECT GET_LOCK(%s, 0)', $name->invoke( null, 'feed_snapshot' ) ) );
		$lookup = $cache->feeds( array( 'spamhaus_drop' ) );
		$this->assertNotInstanceOf( FeedSnapshot::class, $lookup );
		$this->assertTrue( $lookup->contains( (string) inet_pton( '203.0.113.9' ) ) );
		$this->assertFalse( $lookup->contains( (string) inet_pton( '198.51.100.9' ) ) );
		$this->assertFileDoesNotExist( FeedSnapshot::path( array( 'spamhaus_drop' ) ) );
		// Release explicitly: the server frees a closed connection's locks a moment later.
		$other->query( $other->prepare( 'SELECT RELEASE_LOCK(%s)', $name->invoke( null, 'feed_snapshot' ) ) );
		$other->close();

		$cache->flush_feeds();
		$lookup = $cache->feeds( array( 'spamhaus_drop' ) );
		$this->assertInstanceOf( FeedSnapshot::class, $lookup, 'compiled once the lock is free' );
		$this->assertTrue( $lookup->contains( (string) inet_pton( '203.0.113.200' ) ) );
		$this->assertFileExists( FeedSnapshot::path( array( 'spamhaus_drop' ) ) );

		$cache->flush_feeds();
		$this->assertFileDoesNotExist( FeedSnapshot::path( array( 'spamhaus_drop' ) ), 'a feed update removes it' );
	}

	public function test_block_rule_hits_are_buffered_with_a_persistent_cache(): void {
		$c    = Plugin::instance()->container();
		$repo = $c->get( BlockRepository::class );
		$id   = $repo->add( 'block', Cidr::parse( '203.0.113.77' ), 'perf', 'manual' );
		$gate = $c->get( Gate::class );
		$hit  = new \ReflectionMethod( Gate::class, 'count_hit' );
		$hit->setAccessible( true );
		$hits = static fn(): int => (int) $repo->find_exact( 'block', Cidr::parse( '203.0.113.77' ) )['hits'];

		// No persistent cache: written only for logged requests.
		wp_using_ext_object_cache( false );
		$hit->invoke( $gate, $id, false );
		$this->assertSame( 0, $hits() );
		$hit->invoke( $gate, $id, true );
		$this->assertSame( 1, $hits() );

		// Persistent cache: the first hit flushes, the rest wait for the next minute.
		wp_using_ext_object_cache( true );
		for ( $i = 0; $i < 10; $i++ ) {
			$hit->invoke( $gate, $id, false );
		}
		$this->assertSame( 2, $hits(), 'one write for ten hits' );
		wp_cache_delete( 'hits_flush_' . $id, RuleCache::GROUP );
		$hit->invoke( $gate, $id, false );
		$this->assertSame( 12, $hits(), 'the buffered hits are written together' );
	}

	public function test_rule_matches_are_cached_and_retired_by_rule_changes(): void {
		$cache = Plugin::instance()->container()->get( RuleCache::class );
		$calls = 0;
		$find  = static function () use ( &$calls ): array {
			++$calls;
			return array(
				'id'         => 5,
				'expires_at' => null,
			);
		};
		$bin   = (string) inet_pton( '203.0.113.78' );
		wp_using_ext_object_cache( false );
		$cache->block_rule( $bin, $find );
		$cache->block_rule( $bin, $find );
		$this->assertSame( 2, $calls, 'no persistent cache: always the database' );

		wp_using_ext_object_cache( true );
		$calls = 0;
		$cache->block_rule( $bin, $find );
		$cache->block_rule( $bin, $find );
		$this->assertSame( 1, $calls );
		$cache->flush();
		$cache->block_rule( $bin, $find );
		$this->assertSame( 2, $calls, 'a rule change retires cached matches' );
	}

	public function test_batched_deletes_clear_large_tables(): void {
		global $wpdb;
		$table = Plugin::instance()->container()->get( EventRepository::class )->table();
		$old   = gmdate( 'Y-m-d H:i:s', time() - 400 * DAY_IN_SECONDS );
		$rows  = array();
		for ( $i = 0; $i < Batch::SIZE * 2 + 500; $i++ ) {
			$rows[] = $wpdb->prepare( '(%s, %s, %s)', $old, 'blocked', 'ip_gate' );
		}
		$wpdb->query( "INSERT INTO {$table} (created_at, event, module) VALUES " . implode( ',', $rows ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQL.NotPrepared -- Test data, prepared above.
		$this->assertSame( Batch::SIZE * 2 + 500, Plugin::instance()->container()->get( EventRepository::class )->prune( 30 ) );
	}

	public function test_large_file_fingerprints_are_bounded_but_change_with_content(): void {
		$dir   = wp_get_upload_dir()['basedir'];
		$small = $dir . '/ss-fp-small.txt';
		$big   = $dir . '/ss-fp-big.bin';
		$this->files[] = $small;
		$this->files[] = $big;
		file_put_contents( $small, 'hello' );
		$this->assertSame( sha1_file( $small ), IntegrityScanner::fingerprint( $small ) );

		file_put_contents( $big, str_repeat( 'x', 9 * MB_IN_BYTES ) );
		$first = IntegrityScanner::fingerprint( $big );
		$this->assertStringStartsWith( 'big:', $first );
		file_put_contents( $big, '<?php eval($_POST[1]);', FILE_APPEND );
		clearstatcache();
		$this->assertNotSame( $first, IntegrityScanner::fingerprint( $big ), 'appended code changes it' );
	}

	/**
	 * Review 5 (repeated database work): the options every request reads are
	 * fetched in one query; reading them afterwards costs none, and options
	 * that do not exist are remembered as missing.
	 */
	public function test_per_request_options_are_primed_in_one_query(): void {
		global $wpdb;
		update_site_option( 'sentinel_shield_prime_a', array( 'x' => 1 ) );
		update_site_option( 'sentinel_shield_prime_b', 'two' );
		delete_site_option( 'sentinel_shield_prime_missing' );
		$names = array( 'sentinel_shield_prime_a', 'sentinel_shield_prime_b', 'sentinel_shield_prime_missing' );
		wp_cache_flush();
		wp_load_alloptions(); // As in any request, before the plugin loads.
		$before = $wpdb->num_queries;
		\SentinelShield\Support\OptionPrimer::prime( $names );
		$this->assertLessThanOrEqual( 1, $wpdb->num_queries - $before, 'one query (none when cached)' );
		$before = $wpdb->num_queries;
		$this->assertSame( array( 'x' => 1 ), get_site_option( 'sentinel_shield_prime_a' ) );
		$this->assertSame( 'two', get_site_option( 'sentinel_shield_prime_b' ) );
		$this->assertFalse( get_site_option( 'sentinel_shield_prime_missing' ) );
		$this->assertSame( 0, $wpdb->num_queries - $before, 'then read from the cache' );
		\SentinelShield\Support\OptionPrimer::prime( array() );
		update_site_option( 'sentinel_shield_prime_missing', 'now here' );
		$this->assertSame( 'now here', get_site_option( 'sentinel_shield_prime_missing' ), 'a missing one added later is seen' );
		foreach ( $names as $name ) {
			delete_site_option( $name );
		}
	}
}
