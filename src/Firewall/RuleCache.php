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
use SentinelShield\Repository\BlockRepository;
use SentinelShield\Repository\FeedRepository;

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
	 * Compiled sets for this request.
	 *
	 * @var array<string, IpRangeSet>
	 */
	private array $memo = array();

	/**
	 * Compiled feed set for this request.
	 *
	 * @var PackedRangeSet|null
	 */
	private ?PackedRangeSet $feed_memo = null;

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
	 * Compiled union of the given blocklist feeds. Rebuilt when the set of
	 * enabled feeds changes, after a feed update (flush_feeds()), or daily.
	 *
	 * @param list<string> $slugs Enabled feed slugs.
	 */
	public function feeds( array $slugs ): PackedRangeSet {
		sort( $slugs );
		if ( null !== $this->feed_memo && $this->feed_memo_slugs === $slugs ) {
			return $this->feed_memo;
		}
		$this->feed_memo_slugs = $slugs;
		if ( ! $slugs || null === $this->feeds ) {
			$this->feed_memo = PackedRangeSet::empty();
			return $this->feed_memo;
		}
		$data = $this->read( 'feed_set' );
		if ( ! is_array( $data ) || ( $data['feeds'] ?? null ) !== $slugs || ! isset( $data['set'] ) || ! is_array( $data['set'] ) ) {
			$pairs = array();
			foreach ( $this->feeds->ranges( $slugs ) as $row ) {
				$pairs[] = array( (string) hex2bin( (string) $row['start_hex'] ), (string) hex2bin( (string) $row['end_hex'] ) );
			}
			$data = array(
				'feeds' => $slugs,
				'set'   => PackedRangeSet::from_set( IpRangeSet::from_pairs( $pairs ) )->to_storage(),
			);
			$this->write( 'feed_set', $data, DAY_IN_SECONDS );
		}
		$this->feed_memo = PackedRangeSet::from_storage( $data['set'] );
		return $this->feed_memo;
	}

	/**
	 * Invalidates the compiled feed set. Call after any feed update.
	 */
	public function flush_feeds(): void {
		$this->feed_memo = null;
		wp_cache_delete( 'feed_set', self::GROUP );
		delete_site_transient( 'sentinel_shield_feed_set' );
	}

	/**
	 * Compiled set for "block" or "allow".
	 *
	 * @param string $type List type.
	 */
	public function get( string $type ): IpRangeSet {
		if ( isset( $this->memo[ $type ] ) ) {
			return $this->memo[ $type ];
		}
		$key  = 'rules_' . $type;
		$data = $this->read( $key );
		if ( ! is_array( $data ) || (int) ( $data['exp'] ?? 0 ) <= time() || ! isset( $data['ranges'] ) || ! is_array( $data['ranges'] ) ) {
			$data = $this->build( $type );
			$this->write( $key, $data, max( 1, (int) $data['exp'] - time() ) );
		}
		$this->memo[ $type ] = IpRangeSet::from_array( $data['ranges'] );
		return $this->memo[ $type ];
	}

	/**
	 * Invalidates both lists. Call after any rule change.
	 */
	public function flush(): void {
		$this->memo = array();
		foreach ( array( 'rules_block', 'rules_allow' ) as $key ) {
			wp_cache_delete( $key, self::GROUP );
			delete_site_transient( 'sentinel_shield_' . $key );
		}
		do_action( 'sentinel_shield_rules_changed' );
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
		foreach ( $this->repo->active_ranges( $type ) as $row ) {
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
