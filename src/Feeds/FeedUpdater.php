<?php
/**
 * Downloads enabled blocklist feeds on a polite schedule.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Feeds;

use SentinelShield\Firewall\RuleCache;
use SentinelShield\Repository\EventRepository;
use SentinelShield\Repository\FeedRepository;
use SentinelShield\Settings;

defined( 'ABSPATH' ) || exit;

/**
 * Politeness rules, so providers are not hammered and learn as little as possible:
 * - each feed is fetched at most once per max(chosen interval, provider minimum);
 * - conditional requests (ETag / Last-Modified) skip unchanged lists;
 * - a generic User-Agent without the site URL (WordPress's default includes it);
 * - random jitter so sites do not all fetch at the same minute;
 * - exponential backoff after failures, honouring Retry-After on 429/503.
 * A failed or suspiciously small download never replaces the previous copy.
 */
final class FeedUpdater {

	public const STATE_OPTION = 'sentinel_shield_feeds_state';
	public const CRON_HOOK    = 'sentinel_shield_feeds_tick';
	public const MAX_BYTES    = 10485760;
	public const TIME_BUDGET  = 20;

	/**
	 * Constructor.
	 *
	 * @param Settings        $settings Settings.
	 * @param FeedRepository  $repo     Feed storage.
	 * @param RuleCache       $cache    Compiled sets.
	 * @param EventRepository $events   Event log.
	 */
	public function __construct(
		private Settings $settings,
		private FeedRepository $repo,
		private RuleCache $cache,
		private EventRepository $events
	) {}

	/**
	 * Slugs of feeds switched on in settings.
	 *
	 * @return list<string>
	 */
	public function enabled(): array {
		return FeedCatalog::enabled_slugs( $this->settings );
	}

	/**
	 * Seconds between updates of one feed.
	 *
	 * @param string $slug Feed slug.
	 */
	public function interval( string $slug ): int {
		$hours = (int) $this->settings->get( 'feeds.update_hours', 24 );
		$min   = (int) ( FeedCatalog::get( $slug )['min_hours'] ?? 12 );
		return max( $hours, $min ) * HOUR_IN_SECONDS;
	}

	/**
	 * Stored per-feed status.
	 *
	 * @return array<string, array<string, mixed>>
	 */
	public function state(): array {
		$state = get_site_option( self::STATE_OPTION, array() );
		return is_array( $state ) ? $state : array();
	}

	/**
	 * Enabled feeds whose next update is due, soonest first.
	 *
	 * @param int|null $now Current time.
	 * @return list<string>
	 */
	public function due( ?int $now = null ): array {
		$now   = $now ?? time();
		$state = $this->state();
		$due   = array();
		foreach ( $this->enabled() as $slug ) {
			$next = (int) ( $state[ $slug ]['next_due'] ?? 0 );
			if ( $next <= $now ) {
				$due[ $slug ] = $next;
			}
		}
		asort( $due );
		return array_keys( $due );
	}

	/**
	 * Cron entry point: updates due feeds within a time budget, then reschedules
	 * itself shortly if feeds are still waiting (e.g. right after enabling several).
	 *
	 * @return array<string, true|\WP_Error> Results per feed processed.
	 */
	public function tick(): array {
		if ( ! $this->settings->is_enabled() || ! $this->settings->is_module_enabled( 'feeds' ) ) {
			return array();
		}
		$started = time();
		$results = array();
		foreach ( $this->due() as $slug ) {
			if ( time() - $started >= self::TIME_BUDGET ) {
				self::schedule_soon( MINUTE_IN_SECONDS );
				break;
			}
			$results[ $slug ] = $this->update( $slug );
		}
		return $results;
	}

	/**
	 * Schedules a one-off tick. The distinct argument keeps WordPress from
	 * discarding it as a duplicate of the hourly event.
	 *
	 * @param int $delay Seconds from now.
	 */
	public static function schedule_soon( int $delay ): void {
		if ( ! wp_next_scheduled( self::CRON_HOOK, array( 'soon' ) ) ) {
			wp_schedule_single_event( time() + $delay, self::CRON_HOOK, array( 'soon' ) );
		}
	}

	/**
	 * Downloads and stores one feed now.
	 *
	 * @param string $slug  Feed slug.
	 * @param bool   $force Ignore cached validators and download in full.
	 * @return true|\WP_Error
	 */
	public function update( string $slug, bool $force = false ): bool|\WP_Error {
		$feed = FeedCatalog::get( $slug );
		if ( null === $feed ) {
			return new \WP_Error( 'sentinel_shield_feed_unknown', __( 'Unknown blocklist.', 'sentinel-shield' ) );
		}
		$state      = $this->state();
		$entry      = $state[ $slug ] ?? array();
		$validators = $force ? array() : (array) ( $entry['validators'] ?? array() );
		$now        = time();

		$responses = $this->fetch_all( (array) $feed['urls'], $validators );
		if ( is_wp_error( $responses ) ) {
			return $this->fail( $slug, $entry, $responses );
		}

		$entry['last_check'] = $now;
		$unchanged           = ! array_filter( $responses, static fn( array $r ): bool => 304 !== $r['code'] );
		if ( $unchanged && ! empty( $entry['last_success'] ) ) {
			$entry['last_success'] = $now;
			$this->succeed( $slug, $entry );
			return true;
		}
		if ( ! $unchanged && array_filter( $responses, static fn( array $r ): bool => 304 === $r['code'] ) ) {
			// Multi-URL feed with a partial change: every part is needed to rebuild it.
			$responses = $this->fetch_all( (array) $feed['urls'], array() );
			if ( is_wp_error( $responses ) ) {
				return $this->fail( $slug, $entry, $responses );
			}
		}

		$ranges  = array();
		$skipped = 0;
		foreach ( $responses as $response ) {
			$parsed  = FeedParser::parse( (string) $feed['format'], $response['body'] );
			$ranges  = array_merge( $ranges, $parsed['ranges'] );
			$skipped = $skipped + $parsed['skipped'];
		}
		if ( count( $ranges ) < (int) $feed['min_entries'] ) {
			return $this->fail(
				$slug,
				$entry,
				/* translators: 1: number of entries, 2: feed name. */
				new \WP_Error( 'sentinel_shield_feed_small', sprintf( __( 'Only %1$d usable entries downloaded for %2$s, which looks broken; the previous copy was kept.', 'sentinel-shield' ), count( $ranges ), (string) $feed['name'] ) )
			);
		}
		$stored = $this->repo->replace( $slug, $ranges );
		if ( $stored < 0 ) {
			return $this->fail( $slug, $entry, new \WP_Error( 'sentinel_shield_feed_db', __( 'Could not save the downloaded list; the previous copy was kept.', 'sentinel-shield' ) ) );
		}
		$this->cache->flush_feeds();
		// Compile the new snapshot now, in the background job, not in a visitor's request.
		$this->cache->feeds( FeedCatalog::enabled_slugs( $this->settings ) );

		$entry['last_success'] = $now;
		$entry['last_change']  = $now;
		$entry['count']        = $stored;
		$entry['skipped']      = $skipped;
		$entry['validators']   = array();
		foreach ( $responses as $url => $response ) {
			$entry['validators'][ $url ] = $response['validators'];
		}
		$this->succeed( $slug, $entry );
		$this->events->log(
			'feed_updated',
			array(
				'module'  => 'feeds',
				/* translators: 1: feed name, 2: number of ranges. */
				'reason'  => sprintf( __( '%1$s: %2$d ranges', 'sentinel-shield' ), (string) $feed['name'], $stored ),
				'context' => array(
					'feed'    => $slug,
					'ranges'  => $stored,
					'skipped' => $skipped,
				),
			)
		);
		return true;
	}

	/**
	 * Removes stored ranges and status of feeds that are no longer enabled.
	 */
	public function purge_disabled(): void {
		$enabled = $this->enabled();
		$removed = $this->repo->delete_except( $enabled );
		$state   = $this->state();
		$kept    = array_intersect_key( $state, array_flip( $enabled ) );
		if ( count( $kept ) !== count( $state ) ) {
			update_site_option( self::STATE_OPTION, $kept );
		}
		if ( $removed > 0 ) {
			$this->cache->flush_feeds();
			$this->cache->feeds( FeedCatalog::enabled_slugs( $this->settings ) );
		}
	}

	/**
	 * Downloads every URL of a feed.
	 *
	 * @param list<string>                         $urls       URLs.
	 * @param array<string, array<string, string>> $validators Cached ETag / Last-Modified per URL.
	 * @return array<string, array{code:int, body:string, validators:array<string, string>}>|\WP_Error
	 */
	private function fetch_all( array $urls, array $validators ): array|\WP_Error {
		$out = array();
		foreach ( $urls as $url ) {
			$headers = array();
			if ( ! empty( $validators[ $url ]['etag'] ) ) {
				$headers['If-None-Match'] = $validators[ $url ]['etag'];
			}
			if ( ! empty( $validators[ $url ]['modified'] ) ) {
				$headers['If-Modified-Since'] = $validators[ $url ]['modified'];
			}
			$response = wp_safe_remote_get(
				$url,
				array(
					'timeout'             => 20,
					'redirection'         => 3,
					'user-agent'          => 'SentinelShield/' . ( defined( 'SENTINEL_SHIELD_VERSION' ) ? SENTINEL_SHIELD_VERSION : '0' ),
					'headers'             => $headers,
					'limit_response_size' => self::MAX_BYTES,
				)
			);
			if ( is_wp_error( $response ) ) {
				return $response;
			}
			$code = (int) wp_remote_retrieve_response_code( $response );
			if ( 200 !== $code && 304 !== $code ) {
				$retry = (int) wp_remote_retrieve_header( $response, 'retry-after' );
				/* translators: 1: HTTP status code, 2: URL. */
				return new \WP_Error( 'sentinel_shield_feed_http', sprintf( __( 'HTTP %1$d from %2$s.', 'sentinel-shield' ), $code, $url ), array( 'retry_after' => $retry ) );
			}
			$out[ $url ] = array(
				'code'       => $code,
				'body'       => 200 === $code ? (string) wp_remote_retrieve_body( $response ) : '',
				'validators' => 200 === $code
					? array_filter(
						array(
							'etag'     => (string) wp_remote_retrieve_header( $response, 'etag' ),
							'modified' => (string) wp_remote_retrieve_header( $response, 'last-modified' ),
						)
					)
					: (array) ( $validators[ $url ] ?? array() ),
			);
		}
		return $out;
	}

	/**
	 * Records a success and schedules the next regular update with jitter.
	 *
	 * @param string               $slug  Feed slug.
	 * @param array<string, mixed> $entry Status.
	 */
	private function succeed( string $slug, array $entry ): void {
		$entry['error']    = '';
		$entry['failures'] = 0;
		$entry['next_due'] = time() + $this->interval( $slug ) + wp_rand( 0, 30 * MINUTE_IN_SECONDS );
		$this->save_entry( $slug, $entry );
	}

	/**
	 * Records a failure, keeps the old data and backs off: 1 h, 2 h, 4 h ... up to the interval.
	 *
	 * @param string               $slug  Feed slug.
	 * @param array<string, mixed> $entry Status.
	 * @param \WP_Error            $error Error.
	 */
	private function fail( string $slug, array $entry, \WP_Error $error ): \WP_Error {
		$failures            = (int) ( $entry['failures'] ?? 0 ) + 1;
		$data                = $error->get_error_data();
		$retry_after         = is_array( $data ) ? (int) ( $data['retry_after'] ?? 0 ) : 0;
		$backoff             = min( $this->interval( $slug ), HOUR_IN_SECONDS * ( 2 ** min( $failures - 1, 8 ) ) );
		$entry['last_check'] = time();
		$entry['failures']   = $failures;
		$entry['error']      = $error->get_error_message();
		$entry['next_due']   = time() + max( $backoff, $retry_after );
		$this->save_entry( $slug, $entry );
		$this->events->log(
			'feed_error',
			array(
				'module'  => 'feeds',
				'reason'  => mb_substr( (string) ( FeedCatalog::get( $slug )['name'] ?? $slug ) . ': ' . $error->get_error_message(), 0, 255 ),
				'context' => array(
					'feed'     => $slug,
					'failures' => $failures,
				),
			)
		);
		return $error;
	}

	/**
	 * Persists one feed's status.
	 *
	 * @param string               $slug  Feed slug.
	 * @param array<string, mixed> $entry Status.
	 */
	private function save_entry( string $slug, array $entry ): void {
		$state          = $this->state();
		$state[ $slug ] = $entry;
		update_site_option( self::STATE_OPTION, $state );
	}
}
