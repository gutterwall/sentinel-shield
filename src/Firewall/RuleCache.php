<?php
/**
 * Compiled allow/block sets cached in the object cache or transients.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Firewall;

use SentinelShield\Net\IpRangeSet;
use SentinelShield\Net\PackedRangeSet;
use SentinelShield\Net\RangeLookup;
use SentinelShield\Repository\BlockRepository;
use SentinelShield\Repository\FeedRepository;
use SentinelShield\Support\Mutex;

defined( 'ABSPATH' ) || exit;

/**
 * The hot path reads one cache entry per list and does a binary search; the
 * database is only touched on a cache miss or when an IP actually matches.
 * Cache lifetime never exceeds the next rule expiry, so expired rules drop out
 * without an expiry check per request.
 */
final class RuleCache {

	public const GROUP = 'sentinel_shield';

	/**
	 * Seconds an expired compiled list may still be used while it is rebuilt.
	 */
	private const GRACE = 30;

	/**
	 * Compiled sets for this request.
	 *
	 * @var array<string, IpRangeSet>
	 */
	private array $memo = array();

	/**
	 * Compiled feed set for this request.
	 *
	 * @var RangeLookup|null
	 */
	private ?RangeLookup $feed_memo = null;

	/**
	 * Feed slugs the memoized set was built for.
	 *
	 * @var list<string>
	 */
	private array $feed_memo_slugs = array();

	/**
	 * Constructor.
	 *
	 * @param BlockRepository     $repo  Rules repository.
	 * @param FeedRepository|null $feeds Feed ranges repository.
	 */
	public function __construct( private BlockRepository $repo, private ?FeedRepository $feeds = null ) {}

	/**
	 * Union of the given blocklist feeds.
	 *
	 * Normally a binary snapshot file, compiled once (by the feed updater, or by
	 * the first request after a change) and looked up with a few small reads.
	 * While another worker compiles it, the lookup goes to the database for that
	 * request instead of every worker rebuilding the set at once. Without a
	 * writable uploads folder, the compiled set is kept in the cache as before.
	 *
	 * @param list<string> $slugs Enabled feed slugs.
	 */
	public function feeds( array $slugs ): RangeLookup {
		sort( $slugs );
		if ( null !== $this->feed_memo && $this->feed_memo_slugs === $slugs ) {
			return $this->feed_memo;
		}
		$this->feed_memo_slugs = $slugs;
		if ( ! $slugs || null === $this->feeds ) {
			$this->feed_memo = PackedRangeSet::empty();
			return $this->feed_memo;
		}
		$snapshot = new FeedSnapshot( FeedSnapshot::path( $slugs ) );
		if ( $snapshot->valid() ) {
			$this->feed_memo = $snapshot;
			return $snapshot;
		}
		if ( ! Mutex::acquire( 'feed_snapshot', 0 ) ) {
			$this->feed_memo = $this->database_lookup( $slugs );
			return $this->feed_memo;
		}
		try {
			$set = $this->compile_feeds( $slugs );
			if ( FeedSnapshot::write( $set, FeedSnapshot::path( $slugs ) ) ) {
				$this->feed_memo = new FeedSnapshot( FeedSnapshot::path( $slugs ) );
				return $this->feed_memo;
			}
			$this->feed_memo = $this->cached_feeds( $slugs, $set );
			return $this->feed_memo;
		} finally {
			Mutex::release( 'feed_snapshot' );
		}
	}

	/**
	 * Compiles the enabled feeds from the database.
	 *
	 * @param list<string> $slugs Feed slugs.
	 */
	private function compile_feeds( array $slugs ): IpRangeSet {
		$pairs = array();
		foreach ( $this->feeds->ranges( $slugs ) as $row ) {
			$pairs[] = array( (string) hex2bin( (string) $row['start_hex'] ), (string) hex2bin( (string) $row['end_hex'] ) );
		}
		return IpRangeSet::from_pairs( $pairs );
	}

	/**
	 * The compiled set kept in the object cache or a transient (no writable
	 * uploads folder).
	 *
	 * @param list<string> $slugs Feed slugs.
	 * @param IpRangeSet   $set   Freshly compiled set.
	 */
	private function cached_feeds( array $slugs, IpRangeSet $set ): PackedRangeSet {
		$data = $this->read( 'feed_set' );
		if ( ! is_array( $data ) || ( $data['feeds'] ?? null ) !== $slugs || ! isset( $data['set'] ) || ! is_array( $data['set'] ) ) {
			$data = array(
				'feeds' => $slugs,
				'set'   => PackedRangeSet::from_set( $set )->to_storage(),
			);
			$this->write( 'feed_set', $data, DAY_IN_SECONDS );
		}
		return PackedRangeSet::from_storage( $data['set'] );
	}

	/**
	 * One indexed query per lookup, for the moment a snapshot is being built.
	 *
	 * @param list<string> $slugs Feed slugs.
	 */
	private function database_lookup( array $slugs ): RangeLookup {
		$feeds = $this->feeds;
		return new class( $feeds, $slugs ) implements RangeLookup {
			/**
			 * Constructor.
			 *
			 * @param FeedRepository $feeds Feed ranges.
			 * @param list<string>   $slugs Feed slugs.
			 */
			public function __construct( private FeedRepository $feeds, private array $slugs ) {}

			/**
			 * Whether a packed IP is listed.
			 *
			 * @param string $bin Packed IP.
			 */
			public function contains( string $bin ): bool {
				return (bool) $this->feeds->find_containing( $bin, $this->slugs );
			}

			/**
			 * Unknown while compiling.
			 */
			public function count(): int {
				return 0;
			}
		};
	}

	/**
	 * Invalidates the compiled feed set. Call after any feed update.
	 */
	public function flush_feeds(): void {
		$this->feed_memo = null;
		FeedSnapshot::delete_all();
		do_action( 'sentinel_shield_feeds_changed' );
		wp_cache_delete( 'feed_set', self::GROUP );
		delete_site_transient( 'sentinel_shield_feed_set' );
	}

	/**
	 * Compiled set for "block", "allow", or "allow_login" (the allowlist without
	 * automatic administrator entries, which exempt from blocking only).
	 *
	 * @param string $type List type.
	 */
	public function get( string $type ): IpRangeSet {
		if ( isset( $this->memo[ $type ] ) ) {
			return $this->memo[ $type ];
		}
		$key   = 'rules_' . $type;
		$data  = $this->read( $key );
		$valid = is_array( $data ) && isset( $data['ranges'] ) && is_array( $data['ranges'] );
		// Past its expiry, one worker rebuilds; the others keep using the copy
		// for its short grace period instead of all rebuilding at once.
		if ( ! $valid || ( (int) ( $data['exp'] ?? 0 ) <= time() && Mutex::acquire( 'rules_build_' . $type, 0 ) ) ) {
			try {
				$data = $this->build( $type );
				$this->write( $key, $data, max( 1, (int) $data['exp'] - time() ) + self::GRACE );
			} finally {
				Mutex::release( 'rules_build_' . $type );
			}
		}
		$this->memo[ $type ] = IpRangeSet::from_array( $data['ranges'] );
		return $this->memo[ $type ];
	}

	/**
	 * Invalidates both lists. Call after any rule change.
	 */
	public function flush(): void {
		$this->memo = array();
		if ( wp_using_ext_object_cache() ) {
			// Retires every cached rule match at once.
			wp_cache_add( 'rules_version', 0, self::GROUP );
			wp_cache_incr( 'rules_version', 1, self::GROUP );
		}
		foreach ( array( 'rules_block', 'rules_allow', 'rules_allow_login' ) as $key ) {
			wp_cache_delete( $key, self::GROUP );
			delete_site_transient( 'sentinel_shield_' . $key );
		}
		do_action( 'sentinel_shield_rules_changed' );
	}

	/**
	 * The block rule matching an IP. With a persistent object cache the match
	 * is cached for up to a minute (never past the rule's expiry), so a flood
	 * from one IP does not query the rules table on every request; any rule
	 * change retires all cached matches.
	 *
	 * @param string   $bin  Packed IP.
	 * @param callable $find fn(): ?array, the database lookup.
	 * @return array<string, mixed>|null
	 */
	public function block_rule( string $bin, callable $find ): ?array {
		if ( ! wp_using_ext_object_cache() ) {
			return $find();
		}
		$key    = 'match_' . (int) wp_cache_get( 'rules_version', self::GROUP ) . '_' . bin2hex( $bin );
		$found  = false;
		$cached = wp_cache_get( $key, self::GROUP, false, $found );
		if ( $found ) {
			return is_array( $cached ) ? $cached : null;
		}
		$rule = $find();
		$ttl  = MINUTE_IN_SECONDS;
		if ( is_array( $rule ) && ! empty( $rule['expires_at'] ) ) {
			$ttl = max( 1, min( $ttl, (int) strtotime( $rule['expires_at'] . ' UTC' ) - time() ) );
		}
		wp_cache_set( $key, $rule ?? 0, self::GROUP, $ttl );
		return $rule;
	}

	/**
	 * Compiles a list from the database.
	 *
	 * @param string $type List type.
	 * @return array{exp:int, ranges:array<int, mixed>}
	 */
	private function build( string $type ): array {
		$now   = time();
		$next  = $now + HOUR_IN_SECONDS;
		$pairs = array();
		$rows  = 'allow_login' === $type ? $this->repo->active_ranges( 'allow', true ) : $this->repo->active_ranges( $type );
		foreach ( $rows as $row ) {
			$start = (string) hex2bin( (string) $row['start_hex'] );
			$end   = (string) hex2bin( (string) $row['end_hex'] );
			if ( '' === $start || '' === $end ) {
				continue;
			}
			$pairs[] = array( $start, $end );
			if ( ! empty( $row['expires_at'] ) ) {
				$exp = (int) strtotime( $row['expires_at'] . ' UTC' );
				if ( $exp > $now && $exp < $next ) {
					$next = $exp;
				}
			}
		}
		return array(
			'exp'    => $next,
			'ranges' => IpRangeSet::from_pairs( $pairs )->to_array(),
		);
	}

	/**
	 * Reads from the persistent object cache, or the transient fallback.
	 *
	 * @param string $key Key.
	 */
	private function read( string $key ): mixed {
		if ( wp_using_ext_object_cache() ) {
			return wp_cache_get( $key, self::GROUP );
		}
		return get_site_transient( 'sentinel_shield_' . $key );
	}

	/**
	 * Writes to the persistent object cache, or the transient fallback.
	 *
	 * @param string               $key  Key.
	 * @param array<string, mixed> $data Data.
	 * @param int                  $ttl  Seconds.
	 */
	private function write( string $key, array $data, int $ttl ): void {
		if ( wp_using_ext_object_cache() ) {
			wp_cache_set( $key, $data, self::GROUP, $ttl );
			return;
		}
		set_site_transient( 'sentinel_shield_' . $key, $data, $ttl );
	}
}
