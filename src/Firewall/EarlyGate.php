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
	}

	/**
	 * Path of the snapshot.
	 */
	public static function path(): string {
		return GeoUpdater::dir() . '/gate.json';
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
	 * Notes that the snapshot must be rebuilt; it is, once, when the request ends.
	 */
	public function mark_dirty(): void {
		if ( ! $this->wanted() ) {
			return;
		}
		update_site_option( self::DIRTY, time() );
		if ( ! $this->pending ) {
			$this->pending = true;
			add_action( 'shutdown', array( $this, 'rebuild_if_dirty' ) );
		}
	}

	/**
	 * After settings are saved: installs or removes the loader and rebuilds.
	 */
	public function settings_saved(): void {
		$this->settings->refresh();
		$this->sync_loader();
		if ( $this->wanted() ) {
			$this->rebuild();
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
		if ( get_site_option( self::DIRTY ) || $stale ) {
			$this->rebuild();
		}
	}

	/**
	 * Writes the snapshot (and server files) now.
	 *
	 * @return array<string, mixed> The new state: built, valid_until, block and allow counts, error.
	 */
	public function rebuild(): array {
		if ( ! Mutex::acquire( 'early_gate_build', 0 ) ) {
			return (array) get_site_option( self::STATE, array() );
		}
		try {
			delete_site_option( self::DIRTY );
			$data  = $this->compile();
			$dir   = GeoUpdater::dir();
			$error = '';
			if ( ! is_dir( $dir ) && ! wp_mkdir_p( $dir ) ) {
				$error = __( 'The uploads folder is not writable.', 'sentinel-shield' );
			} else {
				GeoUpdater::protect_dir( $dir );
				if ( ! self::write_atomic( self::path(), (string) wp_json_encode( $data['snapshot'] ) ) ) {
					$error = __( 'The snapshot could not be written.', 'sentinel-shield' );
				}
				if ( $this->settings->get( 'firewall.server_files', false ) ) {
					self::write_atomic( $dir . '/nginx-deny.conf', self::nginx( $data['blocked'] ) );
					self::write_atomic( $dir . '/apache-deny.conf', self::apache( $data['blocked'] ) );
				} else {
					foreach ( array( 'nginx-deny.conf', 'apache-deny.conf' ) as $file ) {
						if ( is_file( "$dir/$file" ) ) {
							wp_delete_file( "$dir/$file" );
						}
					}
				}
			}
			$hash  = md5( implode( ',', $data['blocked'] ) );
			$old   = (array) get_site_option( self::STATE, array() );
			$state = array(
				'built'       => time(),
				'valid_until' => (int) $data['snapshot']['valid_until'],
				'block'       => count( $data['blocked'] ),
				'allow'       => (int) $data['allow_count'],
				'feeds'       => '' !== $data['snapshot']['feeds'],
				'hash'        => $hash,
				'error'       => $error,
			);
			update_site_option( self::STATE, $state );
			if ( ( $old['hash'] ?? '' ) !== $hash ) {
				do_action( 'sentinel_shield_blocklist_changed', $data['blocked'] );
			}
			return $state;
		} finally {
			Mutex::release( 'early_gate_build' );
		}
	}

	/**
	 * Builds the snapshot data.
	 *
	 * @return array{snapshot:array<string, mixed>, blocked:list<string>, allow_count:int}
	 */
	public function compile(): array {
		$now     = time();
		$until   = $now + self::MAX_LIFE;
		$pairs   = array();
		$blocked = array();
		foreach ( $this->repo->active_rules( 'block' ) as $row ) {
			if ( $this->gate->is_test_for_source( (string) $row['source'] ) ) {
				continue;
			}
			$start = (string) hex2bin( (string) $row['start_hex'] );
			$end   = (string) hex2bin( (string) $row['end_hex'] );
			if ( '' === $start || '' === $end ) {
				continue;
			}
			$pairs[]   = array( $start, $end );
			$blocked[] = (string) $row['label'];
			if ( ! empty( $row['expires_at'] ) ) {
				$until = min( $until, (int) strtotime( $row['expires_at'] . ' UTC' ) );
			}
		}
		$allow = array();
		foreach ( $this->repo->active_rules( 'allow' ) as $row ) {
			$allow[] = array( (string) hex2bin( (string) $row['start_hex'] ), (string) hex2bin( (string) $row['end_hex'] ) );
			if ( ! empty( $row['expires_at'] ) ) {
				$until = min( $until, (int) strtotime( $row['expires_at'] . ' UTC' ) );
			}
		}
		$feeds = '';
		$slugs = $this->settings->is_module_enabled( 'feeds' ) ? FeedCatalog::enabled_slugs( $this->settings ) : array();
		if ( $slugs && ! $this->settings->is_test_mode_chain( 'feeds', 'ip_gate' ) ) {
			sort( $slugs );
			$lookup = $this->rules->feeds( $slugs );
			if ( $lookup instanceof FeedSnapshot ) {
				$feeds = FeedSnapshot::path( $slugs );
			}
		}
		$proxy   = $this->ips->config();
		$enabled = $this->settings->is_enabled() && $this->settings->is_module_enabled( 'ip_gate' ) && ! SafetyGuard::emergency_disabled();
		return array(
			'snapshot'    => array(
				'v'           => 1,
				'built'       => $now,
				'valid_until' => max( $now + MINUTE_IN_SECONDS, $until ),
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
				'server'      => PackedRangeSet::from_set( $this->guard->server_ranges() )->to_storage(),
				'allow'       => PackedRangeSet::from_set( IpRangeSet::from_pairs( $allow ) )->to_storage(),
				'block'       => PackedRangeSet::from_set( IpRangeSet::from_pairs( $pairs ) )->to_storage(),
				'feeds'       => $feeds,
				'log_max'     => self::LOG_MAX,
			),
			'blocked'     => array_values( array_unique( $blocked ) ),
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
		// early-gate.php looks in wp-content/uploads/sentinel-shield (two levels above the plugin folder).
		return wp_normalize_path( dirname( self::gate_file(), 3 ) . '/uploads/sentinel-shield' ) === wp_normalize_path( GeoUpdater::dir() );
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
	 */
	public static function delete_files(): void {
		foreach ( array( 'gate.json', 'nginx-deny.conf', 'apache-deny.conf', 'early-blocks.log' ) as $file ) {
			$path = GeoUpdater::dir() . '/' . $file;
			if ( is_file( $path ) ) {
				wp_delete_file( $path );
			}
		}
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
	 */
	public static function nginx( array $labels ): string {
		$out = '# Sentinel Shield blocklist for nginx, generated ' . gmdate( 'Y-m-d H:i:s' ) . " UTC. Include it in a server block and reload nginx.\n";
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
	 */
	public static function apache( array $labels ): string {
		$out = '# Sentinel Shield blocklist for Apache 2.4, generated ' . gmdate( 'Y-m-d H:i:s' ) . " UTC. Include it inside a <Directory> or virtual host.\n<RequireAll>\n\tRequire all granted\n";
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
		$log  = GeoUpdater::dir() . '/early-blocks.log';
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
			++$groups[ $key ]['n'];
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
		$tmp = $path . '.' . wp_generate_password( 8, false ) . '.tmp';
		if ( false === @file_put_contents( $tmp, $content ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Our own generated file.
			return false;
		}
		if ( ! @rename( $tmp, $path ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.rename_rename -- Atomic replace.
			wp_delete_file( $tmp );
			return false;
		}
		return true;
	}
}
