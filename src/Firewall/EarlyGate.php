<?php
/**
 * The early firewall's snapshot, loader and server blocklist files.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Firewall;

use SentinelShield\Feeds\FeedCatalog;
use SentinelShield\Geo\GeoUpdater;
use SentinelShield\Net\Cidr;
use SentinelShield\Net\ClientIpFactory;
use SentinelShield\Net\IpAddress;
use SentinelShield\Net\IpRangeSet;
use SentinelShield\Net\PackedRangeSet;
use SentinelShield\Repository\BlockRepository;
use SentinelShield\Repository\EventRepository;
use SentinelShield\Safety\SafetyGuard;
use SentinelShield\Settings;
use SentinelShield\Support\Mutex;
use SentinelShield\Net\RangeMath;
use SentinelShield\Support\DataDir;

defined( 'ABSPATH' ) || exit;

/**
 * WordPress writes what early-gate.php needs into uploads/sentinel-shield/
 * gate.json: the proxy setup, this server's addresses, the allowlist, the
 * enforced block rules (test mode respected), the compiled blocklist feeds and
 * the block page. It is rebuilt after any rule or settings change (once, at
 * the end of that request) and hourly; it carries an expiry (the next rule
 * expiry, at most a day), after which the gate stops using it until it is
 * rebuilt, so an expired lockout never outlives its time.
 *
 * The same data can be written as nginx and Apache deny files and synced to a
 * Cloudflare IP list (CloudflareSync), for blocking before PHP runs at all.
 */
final class EarlyGate {

	public const LOADER   = 'sentinel-shield-early-gate.php';
	public const MARKER   = 'sentinel-shield-early-gate-loader v1';
	public const DIRTY    = 'sentinel_shield_gate_dirty';
	public const STATE    = 'sentinel_shield_gate_state';
	public const LOG_MAX  = 1048576;
	public const MAX_LIFE = DAY_IN_SECONDS;

	public const EXPIRY_HOOK = 'sentinel_shield_gate_expiry';
	public const DEBOUNCE    = 10;
	public const RETRY_AFTER = 300;

	/**
	 * Seconds after which unpublished changes count as overdue (WP-Cron is
	 * not running): a visitor request then publishes them after its response
	 * is sent, and the health screen warns after OVERDUE.
	 */
	public const FALLBACK_AFTER = 120;
	public const OVERDUE        = 360;

	/**
	 * Seconds an explicit build waits for one already running.
	 */
	public const EXPLICIT_WAIT = 15;
	public const LEGACY        = 'sentinel_shield_legacy_files';

	/**
	 * Files 0.8.0 kept in uploads/sentinel-shield that must not stay there.
	 */
	public const LEGACY_SENSITIVE = array( 'gate.json', 'gate-block.bin', 'gate-allow.bin', 'early-blocks.log', 'early-blocks.log.import' );

	/**
	 * Whether a rebuild is scheduled for the end of this request.
	 *
	 * @var bool
	 */
	private bool $pending = false;

	/**
	 * Constructor.
	 *
	 * @param Settings        $settings Settings.
	 * @param BlockRepository $repo     Rules.
	 * @param RuleCache       $rules    Compiled lists and feeds.
	 * @param Gate            $gate     For test mode per rule source.
	 * @param SafetyGuard     $guard    Server addresses.
	 * @param ClientIpFactory $ips      Proxy configuration.
	 * @param EventRepository $events   Event log.
	 */
	public function __construct(
		private Settings $settings,
		private BlockRepository $repo,
		private RuleCache $rules,
		private Gate $gate,
		private SafetyGuard $guard,
		private ClientIpFactory $ips,
		private EventRepository $events
	) {}

	/**
	 * Hooks rebuilds to rule and settings changes.
	 */
	public function register(): void {
		add_action( 'sentinel_shield_rules_changed', array( $this, 'mark_dirty' ) );
		add_action( 'sentinel_shield_feeds_changed', array( $this, 'mark_dirty' ) );
		add_action( 'sentinel_shield_settings_saved', array( $this, 'settings_saved' ) );
		add_action( self::EXPIRY_HOOK, array( $this, 'scheduled_rebuild' ) );
		add_action( 'init', array( self::class, 'maybe_clean_legacy' ) );
	}

	/**
	 * Scheduled build (an action callback returns nothing).
	 */
	public function scheduled_rebuild(): void {
		$this->rebuild();
	}

	/**
	 * Path of the snapshot.
	 */
	public static function path(): string {
		return DataDir::path() . '/gate.json';
	}

	/**
	 * Whether any consumer of the snapshot is switched on.
	 */
	public function wanted(): bool {
		return 'off' !== $this->mode() || $this->settings->get( 'firewall.server_files', false ) || $this->settings->get( 'cloudflare.sync', false );
	}

	/**
	 * How the early firewall is loaded: off, mu_plugin or prepend.
	 */
	public function mode(): string {
		$mode = (string) $this->settings->get( 'firewall.early_gate', 'off' );
		return in_array( $mode, array( 'mu_plugin', 'prepend' ), true ) ? $mode : 'off';
	}

	/**
	 * Whether WordPress enforces IP blocks at all right now. When it does not
	 * (protection off, the IP gate module off, or the emergency constant), every
	 * other layer gets an empty policy too.
	 */
	public function enforcing(): bool {
		return $this->settings->is_enabled() && $this->settings->is_module_enabled( 'ip_gate' ) && ! SafetyGuard::emergency_disabled();
	}

	/**
	 * Notes that the published policy is behind (a durable marker: the change
	 * is published even if this request dies). Administrators, WP-CLI and
	 * cron publish when their request ends; visitor requests (a lockout at the
	 * login form) leave it to a background WP-Cron run, so policy builds stay
	 * off the requests of visitors. WordPress enforces the change at once
	 * either way.
	 */
	public function mark_dirty(): void {
		if ( ! $this->wanted() ) {
			return;
		}
		self::flag_dirty();
		if ( $this->pending ) {
			return;
		}
		$this->pending = true;
		if ( ( is_admin() && ! wp_doing_ajax() ) || wp_doing_cron() || ( defined( 'WP_CLI' ) && WP_CLI ) ) {
			add_action( 'shutdown', array( $this, 'rebuild_if_dirty' ) );
			return;
		}
		$state = (array) get_site_option( self::STATE, array() );
		$at    = max( time(), (int) ( $state['built'] ?? 0 ) + self::DEBOUNCE );
		$next  = wp_next_scheduled( self::EXPIRY_HOOK );
		if ( ! $next || $next > $at ) {
			wp_clear_scheduled_hook( self::EXPIRY_HOOK );
			wp_schedule_single_event( $at, self::EXPIRY_HOOK );
		}
		add_action( 'shutdown', array( $this, 'publish_if_overdue' ) );
	}

	/**
	 * Records an unpublished change: since (the oldest unpublished change) and
	 * last (this one, so a build can tell whether more came in meanwhile).
	 */
	private static function flag_dirty(): void {
		$now   = microtime( true );
		$dirty = self::dirty();
		update_site_option(
			self::DIRTY,
			array(
				'since' => null !== $dirty ? $dirty['since'] : $now,
				'last'  => $now,
			)
		);
	}

	/**
	 * The unpublished-change marker, read from the database (another request
	 * may have changed it since this one loaded its options), or null.
	 *
	 * @return array{since:float, last:float}|null
	 */
	private static function dirty(): ?array {
		global $wpdb;
		$raw = is_multisite()
			? $wpdb->get_var( $wpdb->prepare( 'SELECT meta_value FROM %i WHERE site_id = %d AND meta_key = %s', $wpdb->sitemeta, get_current_network_id(), self::DIRTY ) ) // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Must bypass the options cache.
			: $wpdb->get_var( $wpdb->prepare( 'SELECT option_value FROM %i WHERE option_name = %s', $wpdb->options, self::DIRTY ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Must bypass the options cache.
		if ( null === $raw ) {
			return null;
		}
		$value = maybe_unserialize( $raw );
		if ( is_array( $value ) && isset( $value['since'], $value['last'] ) ) {
			return array(
				'since' => (float) $value['since'],
				'last'  => (float) $value['last'],
			);
		}
		// Older versions stored the time of the change.
		return array(
			'since' => (float) $value,
			'last'  => (float) $value,
		);
	}

	/**
	 * Publication status for the health screen: whether changes are waiting,
	 * since when, and whether that is overdue (background jobs not running).
	 *
	 * @return array{pending:bool, since:int, overdue:bool, next:int}
	 */
	public function publication(): array {
		$dirty = $this->wanted() ? self::dirty() : null;
		$since = null === $dirty ? 0 : (int) $dirty['since'];
		return array(
			'pending' => null !== $dirty,
			'since'   => $since,
			'overdue' => null !== $dirty && $since > 0 && $since < time() - self::OVERDUE,
			'next'    => (int) wp_next_scheduled( self::EXPIRY_HOOK ),
		);
	}

	/**
	 * Shutdown of a visitor request that changed the policy: when unpublished
	 * changes are older than FALLBACK_AFTER (WP-Cron is not running), publishes
	 * them after the response has been sent. Otherwise nudges WP-Cron.
	 */
	public function publish_if_overdue(): void {
		$dirty = self::dirty();
		if ( null === $dirty ) {
			return;
		}
		if ( $dirty['since'] > time() - self::FALLBACK_AFTER ) {
			if ( ! ( defined( 'DISABLE_WP_CRON' ) && DISABLE_WP_CRON ) && function_exists( 'spawn_cron' ) ) {
				spawn_cron();
			}
			return;
		}
		if ( function_exists( 'fastcgi_finish_request' ) ) {
			fastcgi_finish_request();
		} elseif ( function_exists( 'litespeed_finish_request' ) ) {
			litespeed_finish_request();
		}
		$this->rebuild_if_dirty();
	}

	/**
	 * After settings are saved: installs or removes the loader and rebuilds.
	 */
	public function settings_saved(): void {
		$this->settings->refresh();
		$this->sync_loader();
		if ( $this->wanted() ) {
			$this->rebuild( self::EXPLICIT_WAIT );
		} else {
			self::delete_files();
		}
	}

	/**
	 * Rebuilds when marked dirty or about to expire (hourly maintenance, shutdown).
	 */
	public function rebuild_if_dirty(): void {
		if ( ! $this->wanted() ) {
			return;
		}
		$state = get_site_option( self::STATE );
		$stale = ! is_array( $state ) || (int) ( $state['valid_until'] ?? 0 ) < time() + 2 * HOUR_IN_SECONDS;
		if ( null === self::dirty() && ! $stale ) {
			return;
		}
		// During a burst of lockouts, publish at most every DEBOUNCE seconds;
		// WordPress itself enforces each new rule immediately.
		$next = is_array( $state ) ? (int) ( $state['built'] ?? 0 ) + self::DEBOUNCE : 0;
		if ( ! $stale && $next > time() && ! wp_doing_cron() ) {
			if ( ! wp_next_scheduled( self::EXPIRY_HOOK ) || wp_next_scheduled( self::EXPIRY_HOOK ) > $next ) {
				wp_clear_scheduled_hook( self::EXPIRY_HOOK );
				wp_schedule_single_event( $next, self::EXPIRY_HOOK );
			}
			return;
		}
		$this->rebuild();
	}

	/**
	 * Writes the snapshot (and server files) now, if the private folder is ready.
	 *
	 * Background builds give way to one already running (it, or the retry its
	 * marker causes, publishes the change). An explicit build (Rebuild now,
	 * WP-CLI, a settings save) waits for it, and says so if it cannot.
	 *
	 * @param int $wait Seconds to wait for a build already running.
	 * @return array<string, mixed> The new state: built, valid_until, generation, counts, error.
	 */
	public function rebuild( int $wait = 0 ): array {
		if ( ! Mutex::acquire( 'early_gate_build', $wait ) ) {
			$state = (array) get_site_option( self::STATE, array() );
			if ( $wait > 0 ) {
				$state['error'] = __( 'Another build of the snapshot is still running; it was not rebuilt now. Try again in a minute.', 'sentinel-shield' );
			}
			return $state;
		}
		try {
			// Cleared only once this build is recorded, and only if no change
			// came in meanwhile: a build that dies half-way is redone.
			$dirty  = self::dirty();
			$data   = $this->compile();
			$dir    = DataDir::path();
			$old    = (array) get_site_option( self::STATE, array() );
			$hash   = md5( implode( ',', $data['blocked'] ) );
			$gen    = (int) ( $old['generation'] ?? 0 ) + ( ( $old['hash'] ?? '' ) !== $hash ? 1 : 0 );
			$errors = array();
			$files  = (array) ( $old['files'] ?? array() );
			$pub    = (int) ( $old['published'] ?? 0 );
			$srv    = (int) ( $old['server_generation'] ?? 0 );
			if ( true !== DataDir::is_private() ) {
				// Never write the policy, the log or server files where they could be downloaded.
				$errors[] = DataDir::problem();
				self::delete_files( false );
				$files = array();
				$pub   = 0;
				$srv   = 0;
			} else {
				$published = $this->publish( $dir, $data, $gen );
				if ( is_array( $published ) ) {
					$files = $published;
					$pub   = $gen;
				} else {
					$errors[] = $published;
				}
				if ( $this->settings->get( 'firewall.server_files', false ) ) {
					if ( self::write_atomic( $dir . '/nginx-deny.conf', self::nginx( $data['blocked'], $gen ) ) && self::write_atomic( $dir . '/apache-deny.conf', self::apache( $data['blocked'], $gen ) ) ) {
						$srv = $gen;
					} else {
						$errors[] = __( 'The server blocklist files could not be written; the web server keeps the previous version.', 'sentinel-shield' );
					}
				} else {
					self::empty_server_files();
					$srv = 0;
				}
			}
			$state = array(
				'built'             => time(),
				'valid_until'       => (int) $data['snapshot']['valid_until'],
				'block'             => count( $data['blocked'] ),
				'allow'             => (int) $data['allow_count'],
				'feeds'             => '' !== $data['snapshot']['feeds'],
				'enforcing'         => (bool) $data['snapshot']['enabled'],
				'hash'              => $hash,
				'generation'        => $gen,
				'published'         => $pub,
				'server_generation' => $srv,
				'files'             => $files,
				'error'             => implode( ' ', array_filter( $errors ) ),
			);
			do_action( 'sentinel_shield_checkpoint', 'gate:before_state' );
			update_site_option( self::STATE, $state );
			if ( null !== $dirty && self::dirty() === $dirty ) {
				delete_site_option( self::DIRTY );
			}
			// Rebuild again when the next rule expires, so short lockouts end in
			// every layer soon after (WP-Cron can run late; WordPress itself
			// checks expiry on every request).
			wp_clear_scheduled_hook( self::EXPIRY_HOOK );
			$next = $state['valid_until'] < time() + self::MAX_LIFE ? $state['valid_until'] + 1 : 0;
			if ( $pub !== $gen && true === DataDir::is_private() ) {
				// A failed publication is retried; the previous snapshot stays in use meanwhile.
				self::flag_dirty();
				$next = $next ? min( $next, time() + self::RETRY_AFTER ) : time() + self::RETRY_AFTER;
			}
			if ( $next ) {
				wp_schedule_single_event( $next, self::EXPIRY_HOOK );
			}
			if ( ( $old['hash'] ?? '' ) !== $hash ) {
				do_action( 'sentinel_shield_blocklist_changed', $data['blocked'] );
			}
			return $state;
		} finally {
			Mutex::release( 'early_gate_build' );
		}
	}

	/**
	 * The policy of the published generation, read back from its range files,
	 * so Cloudflare mirrors exactly what was published instead of compiling
	 * again. Null when the published snapshot is not the current generation,
	 * has expired, or cannot be read.
	 *
	 * @return array{blocked:list<string>, allow_set:IpRangeSet, generation:int}|null
	 */
	public function published_policy(): ?array {
		$state = (array) get_site_option( self::STATE, array() );
		$files = (array) ( $state['files'] ?? array() );
		if ( empty( $state['generation'] ) || (int) ( $state['published'] ?? 0 ) !== (int) $state['generation'] || (int) ( $state['valid_until'] ?? 0 ) <= time() || empty( $files['block'] ) || empty( $files['allow'] ) ) {
			return null;
		}
		$block = FeedSnapshot::read_set( (string) $files['block'] );
		$allow = FeedSnapshot::read_set( (string) $files['allow'] );
		if ( null === $block || null === $allow ) {
			return null;
		}
		return array(
			'blocked'    => RangeMath::cidrs( $block ),
			'allow_set'  => $allow,
			'generation' => (int) $state['generation'],
		);
	}

	/**
	 * Publishes one complete policy generation: both range files under names
	 * unique to this build, each verified, and then the manifest (gate.json)
	 * that points at them, replaced in one atomic rename. Until that rename the
	 * previous manifest and its files stay in use, so a request never sees a
	 * mix of two generations. Files from older builds are removed afterwards,
	 * except the previous one (a request may still be reading it).
	 *
	 * @param string               $dir  Private folder.
	 * @param array<string, mixed> $data compile() result.
	 * @param int                  $gen  Generation number.
	 * @return array{block:string, allow:string}|string The new files, or an error.
	 */
	private function publish( string $dir, array $data, int $gen ): array|string {
		$tag   = $gen . '-' . bin2hex( random_bytes( 4 ) );
		$block = "$dir/gate-block-$tag.bin";
		$allow = "$dir/gate-allow-$tag.bin";
		$snap  = $data['snapshot'] + array(
			'generation' => $gen,
			'block_file' => $block,
			'allow_file' => $allow,
		);
		$ok    = FeedSnapshot::write( $data['block_set'], $block ) && self::verify( $block, $data['block_set'] )
			&& FeedSnapshot::write( $data['allow_set'], $allow ) && self::verify( $allow, $data['allow_set'] );
		/**
		 * Fault-injection point for tests (a worker killed at a step of the
		 * build); has no other use.
		 *
		 * @param string $step Step reached.
		 */
		do_action( 'sentinel_shield_checkpoint', 'gate:ranges_written' );
		$ok = $ok && self::write_atomic( self::path(), (string) wp_json_encode( $snap ) );
		do_action( 'sentinel_shield_checkpoint', 'gate:manifest_replaced' );
		if ( ! $ok ) {
			foreach ( array( $block, $allow ) as $file ) {
				if ( is_file( $file ) ) {
					wp_delete_file( $file );
				}
			}
			return __( 'The snapshot could not be written completely; the early firewall keeps using the previous one, and the build is retried in five minutes.', 'sentinel-shield' );
		}
		$old  = (array) ( ( (array) get_site_option( self::STATE, array() ) )['files'] ?? array() );
		$keep = array_merge( array( $block, $allow ), array_values( array_map( 'strval', $old ) ) );
		foreach ( self::snapshot_files( $dir ) as $file ) {
			// Older range files, and temporary files a killed build left behind.
			$stray = str_ends_with( $file, '.tmp' ) && (int) @filemtime( $file ) < time() - 10 * MINUTE_IN_SECONDS; // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Vanished meanwhile.
			if ( $stray || ( str_ends_with( $file, '.bin' ) && ! in_array( $file, $keep, true ) ) ) {
				wp_delete_file( $file );
			}
		}
		return array(
			'block' => $block,
			'allow' => $allow,
		);
	}

	/**
	 * Whether a written range file has the expected header and size.
	 *
	 * @param string     $file File.
	 * @param IpRangeSet $set  What was written.
	 */
	private static function verify( string $file, IpRangeSet $set ): bool {
		clearstatcache( true, $file );
		$head = is_readable( $file ) ? (string) file_get_contents( $file, false, null, 0, 16 ) : ''; // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file.
		if ( 16 !== strlen( $head ) || FeedSnapshot::MAGIC !== substr( $head, 0, 8 ) ) {
			return false;
		}
		$n4 = count( $set->pairs( 4 ) );
		$n6 = count( $set->pairs( 6 ) );
		return pack( 'NN', $n4, $n6 ) === substr( $head, 8 ) && (int) filesize( $file ) === 16 + 8 * $n4 + 32 * $n6;
	}

	/**
	 * The snapshot's files in a folder: gate.json, range files and leftovers.
	 *
	 * @param string $dir Folder.
	 * @return list<string>
	 */
	private static function snapshot_files( string $dir ): array {
		$files = array_merge( array( "$dir/gate.json" ), (array) glob( "$dir/gate-block*.bin" ), (array) glob( "$dir/gate-allow*.bin" ), (array) glob( "$dir/*.tmp" ) );
		return array_values( array_filter( $files, static fn( $f ): bool => is_string( $f ) && is_file( $f ) ) );
	}

	/**
	 * Builds the effective policy: enforced block rules minus the allowlist and
	 * this server's addresses, so every layer (early firewall, web server,
	 * Cloudflare) blocks exactly what WordPress itself would. With enforcement
	 * off, the policy is empty.
	 *
	 * @return array{snapshot:array<string, mixed>, blocked:list<string>, block_set:IpRangeSet, allow_set:IpRangeSet, allow_count:int}
	 */
	public function compile(): array {
		$now     = time();
		$until   = $now + self::MAX_LIFE;
		$enabled = $this->enforcing();
		$pairs   = array();
		if ( $enabled ) {
			foreach ( $this->repo->active_rules( 'block' ) as $row ) {
				if ( $this->gate->is_test_for_source( (string) $row['source'] ) ) {
					continue;
				}
				$start = (string) hex2bin( (string) $row['start_hex'] );
				$end   = (string) hex2bin( (string) $row['end_hex'] );
				if ( '' === $start || '' === $end ) {
					continue;
				}
				$pairs[] = array( $start, $end );
				if ( ! empty( $row['expires_at'] ) ) {
					$until = min( $until, (int) strtotime( $row['expires_at'] . ' UTC' ) );
				}
			}
		}
		$allow = array();
		foreach ( $this->repo->active_rules( 'allow' ) as $row ) {
			$allow[] = array( (string) hex2bin( (string) $row['start_hex'] ), (string) hex2bin( (string) $row['end_hex'] ) );
			if ( ! empty( $row['expires_at'] ) ) {
				$until = min( $until, (int) strtotime( $row['expires_at'] . ' UTC' ) );
			}
		}
		$server    = $this->guard->server_ranges();
		$allow_set = IpRangeSet::from_pairs( $allow );
		$exempt    = IpRangeSet::from_pairs( array_merge( $allow_set->pairs( 4 ), $allow_set->pairs( 6 ), $server->pairs( 4 ), $server->pairs( 6 ) ) );
		$block_set = RangeMath::subtract( IpRangeSet::from_pairs( $pairs ), $exempt );
		$feeds     = '';
		$slugs     = $enabled && $this->settings->is_module_enabled( 'feeds' ) ? FeedCatalog::enabled_slugs( $this->settings ) : array();
		if ( $slugs && ! $this->settings->is_test_mode_chain( 'feeds', 'ip_gate' ) ) {
			sort( $slugs );
			$lookup = $this->rules->feeds( $slugs );
			if ( $lookup instanceof FeedSnapshot ) {
				$feeds = FeedSnapshot::path( $slugs );
			}
		}
		$proxy = $this->ips->config();
		return array(
			'snapshot'    => array(
				'v'           => 2,
				'built'       => $now,
				'valid_until' => max( $now + 1, $until ),
				'enabled'     => $enabled,
				'status'      => '404' === $this->settings->get( 'general.block_response' ) ? 404 : 403,
				'page'        => BlockPage::early_template( $this->settings ),
				'reason_rule' => __( 'Your IP address is on this site\'s blocklist.', 'sentinel-shield' ),
				'reason_feed' => __( 'Your IP address is on a public blocklist this site uses.', 'sentinel-shield' ),
				'proxy'       => array(
					'mode'    => $proxy['mode'],
					'header'  => $proxy['header'],
					'trusted' => PackedRangeSet::from_set( IpRangeSet::from_strings( $proxy['cidrs'] ) )->to_storage(),
				),
				'server'      => PackedRangeSet::from_set( $server )->to_storage(),
				'feeds'       => $feeds,
				'log_max'     => self::LOG_MAX,
			),
			'blocked'     => RangeMath::cidrs( $block_set ),
			'block_set'   => $block_set,
			'allow_set'   => $exempt,
			'allow_count' => count( $allow ),
		);
	}

	/**
	 * Whether the gate ran for the current request, and how: '', 'prepend' or 'mu'.
	 */
	public static function active_as(): string {
		return defined( 'SENTINEL_SHIELD_EARLY_GATE' ) ? (string) SENTINEL_SHIELD_EARLY_GATE : '';
	}

	/**
	 * The gate file inside the plugin.
	 */
	public static function gate_file(): string {
		return dirname( SENTINEL_SHIELD_FILE ) . '/early-gate.php';
	}

	/**
	 * Whether the snapshot is where early-gate.php looks for it by default.
	 */
	public static function default_location(): bool {
		// early-gate.php looks for sentinel-shield-data next to the WordPress folder (four levels above itself).
		return wp_normalize_path( dirname( self::gate_file(), 4 ) . '/' . DataDir::NAME ) === wp_normalize_path( DataDir::path() );
	}

	/**
	 * Path of the must-use loader.
	 */
	public static function loader_path(): string {
		return WPMU_PLUGIN_DIR . '/' . self::LOADER;
	}

	/**
	 * Contents of the must-use loader.
	 */
	public static function loader_code(): string {
		$gate   = var_export( wp_normalize_path( self::gate_file() ), true ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_var_export -- Writes a PHP string literal.
		$config = var_export( wp_normalize_path( self::path() ), true ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_var_export -- See above.
		return "<?php\n/**\n * Plugin Name: Sentinel Shield early firewall\n * Description: Runs Sentinel Shield's firewall before other plugins load. Managed by Sentinel Shield (Settings → Server & CDN); it is removed when the setting is turned off or the plugin is deactivated.\n */\n\n// " . self::MARKER . "\n\$sentinel_shield_gate_config = $config;\nif ( is_readable( $gate ) ) {\n\trequire_once $gate;\n}\n";
	}

	/**
	 * Whether a file is this plugin's loader (for the malware scan).
	 *
	 * @param string $path File.
	 */
	public static function is_own_loader( string $path ): bool {
		return is_file( $path ) && (string) file_get_contents( $path ) === self::loader_code(); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file.
	}

	/**
	 * Whether a file is this plugin's gate (for the malware scan's auto-prepend check).
	 *
	 * @param string $path File.
	 */
	public static function is_own_gate( string $path ): bool {
		$real = realpath( $path );
		return false !== $real && realpath( self::gate_file() ) === $real;
	}

	/**
	 * Installs or removes the must-use loader to match the setting.
	 *
	 * @return string '' on success, else an error message.
	 */
	public function sync_loader(): string {
		$path = self::loader_path();
		if ( 'mu_plugin' !== $this->mode() ) {
			self::remove_loader();
			return '';
		}
		if ( self::is_own_loader( $path ) ) {
			return '';
		}
		if ( ! is_dir( WPMU_PLUGIN_DIR ) && ! wp_mkdir_p( WPMU_PLUGIN_DIR ) ) {
			return __( 'The mu-plugins folder could not be created.', 'sentinel-shield' );
		}
		return self::write_atomic( $path, self::loader_code() ) ? '' : __( 'The loader could not be written to the mu-plugins folder.', 'sentinel-shield' );
	}

	/**
	 * Removes the must-use loader (only if it is ours).
	 */
	public static function remove_loader(): void {
		$path = self::loader_path();
		if ( is_file( $path ) && str_contains( (string) file_get_contents( $path ), self::MARKER ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file.
			wp_delete_file( $path );
		}
	}

	/**
	 * Removes the snapshot and server files.
	 *
	 * @param bool $state Also forget the build state.
	 */
	public static function delete_files( bool $state = true ): void {
		$dir = DataDir::path();
		foreach ( array_merge( self::snapshot_files( $dir ), array( "$dir/early-blocks.log" ) ) as $file ) {
			if ( is_file( $file ) ) {
				wp_delete_file( $file );
			}
		}
		// Emptied, not deleted: nginx and Apache refuse to reload when a file they include is missing.
		self::empty_server_files();
		if ( $state ) {
			delete_site_option( self::STATE );
			wp_clear_scheduled_hook( self::EXPIRY_HOOK );
		}
	}

	/**
	 * Removes what 0.8.0 left in the public uploads folder: the snapshot (with
	 * allowlisted addresses), the range files and the block log are deleted;
	 * the server blocklist files are replaced with a stub that blocks nothing
	 * and says where the list moved, because deleting a file that nginx or
	 * Apache includes would stop the server from reloading. Safe to run again;
	 * the result (including files that could not be removed) is stored.
	 *
	 * @return array{checked:int, removed:list<string>, stubbed:list<string>, failed:list<string>}
	 */
	public static function clean_legacy(): array {
		$dir    = GeoUpdater::dir();
		$result = array(
			'checked' => time(),
			'removed' => array(),
			'stubbed' => array(),
			'failed'  => array(),
		);
		$doomed = array_map( static fn( string $f ): string => "$dir/$f", self::LEGACY_SENSITIVE );
		foreach ( array_merge( $doomed, (array) glob( $dir . '/gate*.tmp' ), (array) glob( $dir . '/*-deny.conf.*.tmp' ) ) as $file ) {
			if ( ! is_string( $file ) || ! file_exists( $file ) ) {
				continue;
			}
			wp_delete_file( $file );
			clearstatcache( true, $file );
			$result[ file_exists( $file ) ? 'failed' : 'removed' ][] = $file;
		}
		foreach ( array(
			'nginx-deny.conf'  => "# Sentinel Shield: this file is no longer updated and blocks nothing. The blocklist moved to the\n# private folder shown on Settings → Server & CDN. Change the include line to the one shown there,\n# check and reload nginx (nginx -t && nginx -s reload), then delete this file.\n",
			'apache-deny.conf' => "# Sentinel Shield: this file is no longer updated and blocks nothing. The blocklist moved to the\n# private folder shown on Settings → Server & CDN. Change the Include line to the one shown there,\n# check and reload Apache (apachectl configtest && apachectl graceful), then delete this file.\n",
		) as $name => $stub ) {
			$file = "$dir/$name";
			if ( ! is_file( $file ) ) {
				continue;
			}
			if ( (string) file_get_contents( $file ) === $stub ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file.
				$result['stubbed'][] = $file;
				continue;
			}
			$result[ self::write_atomic( $file, $stub ) ? 'stubbed' : 'failed' ][] = $file;
		}
		update_site_option( self::LEGACY, $result );
		return $result;
	}

	/**
	 * Notes that the legacy cleanup must run (from the upgrade migration).
	 */
	public static function mark_legacy_pending(): void {
		update_site_option( self::LEGACY, array( 'pending' => true ) + self::legacy_state() );
	}

	/**
	 * Runs the legacy cleanup when it is pending or something failed last time
	 * (on init after an upgrade, and from hourly maintenance).
	 */
	public static function maybe_clean_legacy(): void {
		$state = self::legacy_state();
		if ( ! empty( $state['pending'] ) || ! empty( $state['failed'] ) ) {
			self::clean_legacy();
		}
	}

	/**
	 * Result of the last legacy cleanup (empty when there was nothing to do).
	 *
	 * @return array<string, mixed>
	 */
	public static function legacy_state(): array {
		$state = get_site_option( self::LEGACY );
		return is_array( $state ) ? $state : array();
	}

	/**
	 * Replaces existing server blocklist files with empty ones (an include of a
	 * missing file would stop nginx or Apache from reloading).
	 */
	public static function empty_server_files(): void {
		$dir = DataDir::path();
		if ( is_file( $dir . '/nginx-deny.conf' ) ) {
			self::write_atomic( $dir . '/nginx-deny.conf', self::nginx( array() ) );
		}
		if ( is_file( $dir . '/apache-deny.conf' ) ) {
			self::write_atomic( $dir . '/apache-deny.conf', self::apache( array() ) );
		}
	}

	/**
	 * Plugin deactivation: the early firewall stops (its snapshot is removed, so
	 * an auto_prepend_file line left behind lets everything through) and the
	 * server files are emptied. Cloudflare is cleared separately.
	 */
	public static function deactivate(): void {
		self::remove_loader();
		$dir = DataDir::path();
		foreach ( array_merge( self::snapshot_files( $dir ), array( "$dir/early-blocks.log" ) ) as $path ) {
			if ( is_file( $path ) ) {
				wp_delete_file( $path );
			}
		}
		self::empty_server_files();
		wp_clear_scheduled_hook( self::EXPIRY_HOOK );
		delete_site_option( self::STATE );
	}

	/**
	 * Lines for php.ini, .user.ini, Apache and nginx to load the gate first.
	 *
	 * @return array<string, string>
	 */
	public static function prepend_snippets(): array {
		$gate = wp_normalize_path( self::gate_file() );
		$out  = array(
			'php.ini / .user.ini' => 'auto_prepend_file = "' . $gate . '"',
			'Apache (mod_php)'    => 'php_value auto_prepend_file "' . $gate . '"',
			'nginx (PHP-FPM)'     => 'fastcgi_param PHP_VALUE "auto_prepend_file=' . $gate . '";',
		);
		if ( ! self::default_location() ) {
			$out['nginx (snapshot location)']  = 'fastcgi_param SENTINEL_SHIELD_GATE_CONFIG "' . wp_normalize_path( self::path() ) . '";';
			$out['Apache (snapshot location)'] = 'SetEnv SENTINEL_SHIELD_GATE_CONFIG "' . wp_normalize_path( self::path() ) . '"';
		}
		return $out;
	}

	/**
	 * Blocked ranges as an nginx include file.
	 *
	 * @param list<string> $labels CIDR labels.
	 * @param int          $gen    Policy generation.
	 */
	public static function nginx( array $labels, int $gen = 0 ): string {
		$out = '# Sentinel Shield blocklist for nginx, policy generation ' . $gen . ', generated ' . gmdate( 'Y-m-d H:i:s' ) . " UTC. Include it in a server block and reload nginx.\n";
		foreach ( $labels as $label ) {
			if ( null !== Cidr::parse( $label ) ) {
				$out .= 'deny ' . $label . ";\n";
			}
		}
		return $out;
	}

	/**
	 * Blocked ranges as an Apache 2.4 include file.
	 *
	 * @param list<string> $labels CIDR labels.
	 * @param int          $gen    Policy generation.
	 */
	public static function apache( array $labels, int $gen = 0 ): string {
		$out = '# Sentinel Shield blocklist for Apache 2.4, policy generation ' . $gen . ', generated ' . gmdate( 'Y-m-d H:i:s' ) . " UTC. Include it inside a <Directory> or virtual host.\n<RequireAll>\n\tRequire all granted\n";
		foreach ( $labels as $label ) {
			if ( null !== Cidr::parse( $label ) ) {
				$out .= "\tRequire not ip " . $label . "\n";
			}
		}
		return $out . "</RequireAll>\n";
	}

	/**
	 * Imports blocks noted by the early firewall into the event log, one event
	 * per IP per minute with a count.
	 *
	 * @return int Events written.
	 */
	public function import_log(): int {
		$log  = DataDir::path() . '/early-blocks.log';
		$work = $log . '.import';
		if ( ! is_file( $log ) || ! @rename( $log, $work ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.rename_rename -- Atomic hand-over from the gate.
			return 0;
		}
		$groups = array();
		$h      = fopen( $work, 'rb' ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- Our own log file.
		$lines  = 0;
		while ( false !== $h && ! feof( $h ) && $lines < 20000 ) {
			$row = json_decode( (string) fgets( $h ), true );
			++$lines;
			if ( ! is_array( $row ) || null === IpAddress::normalize( (string) ( $row['ip'] ?? '' ) ) ) {
				continue;
			}
			$key = $row['ip'] . '|' . intdiv( (int) $row['t'], 60 );
			if ( ! isset( $groups[ $key ] ) ) {
				$groups[ $key ] = $row + array( 'n' => 0 );
			}
			// Sampled lines (during floods) stand for several blocks.
			$groups[ $key ]['n'] += max( 1, min( 100, (int) ( $row['s'] ?? 1 ) ) );
		}
		if ( false !== $h ) {
			fclose( $h ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- Our own log file.
		}
		wp_delete_file( $work );
		$written = 0;
		foreach ( array_slice( $groups, 0, 500 ) as $row ) {
			$this->events->log(
				'blocked',
				array(
					'ip'         => (string) $row['ip'],
					'module'     => 'early_gate',
					/* translators: 1: reason, 2: number of requests. */
					'reason'     => mb_substr( sprintf( __( '%1$s (early firewall, %2$d requests)', 'sentinel-shield' ), (string) $row['r'], (int) $row['n'] ), 0, 255 ),
					'uri'        => (string) ( $row['u'] ?? '' ),
					'user_agent' => (string) ( $row['a'] ?? '' ),
					'context'    => array(
						'count' => (int) $row['n'],
						'time'  => (int) $row['t'],
					),
				)
			);
			++$written;
		}
		return $written;
	}

	/**
	 * Writes a file atomically (temporary name, then rename).
	 *
	 * @param string $path    Destination.
	 * @param string $content Content.
	 */
	private static function write_atomic( string $path, string $content ): bool {
		$tmp = $path . '.' . bin2hex( random_bytes( 4 ) ) . '.tmp';
		// A short write (disk full, quota) leaves the old file in place.
		if ( strlen( $content ) !== @file_put_contents( $tmp, $content ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Our own generated file.
			if ( is_file( $tmp ) ) {
				wp_delete_file( $tmp );
			}
			return false;
		}
		if ( ! @rename( $tmp, $path ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.rename_rename -- Atomic replace.
			wp_delete_file( $tmp );
			return false;
		}
		return true;
	}
}
