<?php
/**
 * Read-only scan for the persistence points used by the SC WordPress malware.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Lockdown;

use SentinelShield\Cron\CronInspector;
use SentinelShield\Repository\EventRepository;
use SentinelShield\Settings;

defined( 'ABSPATH' ) || exit;

/**
 * SC keeps copies of itself in about eight places (an auto_prepend_file loader,
 * drop-ins, a must-use plugin and a regular plugin, the theme, a ZIP bundle, a
 * database option and shared memory) and each copy restores the others. The scan
 * looks at all of them in one pass and never changes anything: deleting files in
 * the wrong order makes SC rewrite them, so cleanup stays a deliberate step.
 *
 * Files that are not malicious but cannot be told apart automatically (drop-ins,
 * must-use plugins) are reported once and can be approved; an approved file is
 * reported again if its contents change.
 */
final class IntegrityScanner {

	public const REPORT_OPTION   = 'sentinel_shield_scan_report';
	public const BASELINE_OPTION = 'sentinel_shield_scan_baseline';

	public const SEVERITIES = array( 'critical', 'warning', 'notice', 'ok' );

	private const MAX_ENTRIES   = 20000;
	private const MAX_READ      = 2097152;
	private const MAX_PER_CHECK = 100;
	private const TIME_BUDGET   = 20.0;

	/**
	 * Findings of the current run.
	 *
	 * @var list<array<string, mixed>>
	 */
	private array $findings = array();

	/**
	 * Checks that ran out of time or entries.
	 *
	 * @var list<string>
	 */
	private array $truncated = array();

	/**
	 * Run deadline (microtime).
	 *
	 * @var float
	 */
	private float $deadline = 0.0;

	/**
	 * Constructor.
	 *
	 * @param AdminRegistry   $admins   Administrator registry.
	 * @param EventRepository $events   Event log.
	 * @param Settings        $settings Settings.
	 */
	public function __construct( private AdminRegistry $admins, private EventRepository $events, private Settings $settings ) {}

	/**
	 * The checks, with what SC does at each place.
	 *
	 * @return array<string, array{0:string, 1:string}>
	 */
	public static function checks(): array {
		return array(
			'prepend'        => array( __( 'PHP auto-prepend loaders', 'sentinel-shield' ), __( 'SC starts from an auto_prepend_file line in .user.ini, php.ini or .htaccess that loads a hidden PHP file before every request.', 'sentinel-shield' ) ),
			'dropins'        => array( __( 'Drop-in files', 'sentinel-shield' ), __( 'SC hides full copies of itself in wp-content/db.php and advanced-cache.php, which run before any plugin.', 'sentinel-shield' ) ),
			'mu_plugins'     => array( __( 'Must-use plugins', 'sentinel-shield' ), __( 'SC installs its backdoor as a must-use plugin (which cannot be deactivated) and as a regular plugin with the same name.', 'sentinel-shield' ) ),
			'hidden_plugins' => array( __( 'Hidden plugins', 'sentinel-shield' ), __( 'SC removes its plugin from the Plugins screen and from update checks.', 'sentinel-shield' ) ),
			'admins'         => array( __( 'Administrator accounts', 'sentinel-shield' ), __( 'SC writes an administrator straight into the database and hides it from the Users screen.', 'sentinel-shield' ) ),
			'triggers'       => array( __( 'Database triggers', 'sentinel-shield' ), __( 'Related SC variants add database triggers that recreate a deleted administrator.', 'sentinel-shield' ) ),
			'theme'          => array( __( 'Theme code injection', 'sentinel-shield' ), __( 'SC appends a marked block to the theme\'s functions.php that re-creates the plugin.', 'sentinel-shield' ) ),
			'stray_files'    => array( __( 'Hidden PHP files and restore bundles', 'sentinel-shield' ), __( 'SC uses dot-prefixed PHP loaders, a randomly named PHP shim and a randomly named ZIP restore bundle; web shells often sit in uploads.', 'sentinel-shield' ) ),
			'options'        => array( __( 'Encoded payloads in the database', 'sentinel-shield' ), __( 'SC stores a compressed, base64-encoded copy of itself in a randomly named option, plus sc_ control options.', 'sentinel-shield' ) ),
			'cron'           => array( __( 'Scheduled task persistence', 'sentinel-shield' ), __( 'SC schedules randomly named WP-Cron tasks that redeploy it.', 'sentinel-shield' ) ),
			'hooks'          => array( __( 'Login and hiding hooks', 'sentinel-shield' ), __( 'SC hooks into logins to capture credentials and into admin screens to hide itself.', 'sentinel-shield' ) ),
			'shm'            => array( __( 'Shared memory', 'sentinel-shield' ), __( 'SC keeps a copy of itself in System V shared memory, which survives file and database cleanup.', 'sentinel-shield' ) ),
			'outbound'       => array( __( 'Blockchain command channel', 'sentinel-shield' ), __( 'SC reads its instructions from an Ethereum smart contract through public RPC gateways.', 'sentinel-shield' ) ),
		);
	}

	/**
	 * Runs every check and stores the report.
	 *
	 * @return array{time:int, duration:float, findings:list<array<string, mixed>>, truncated:list<string>, new:list<string>}
	 */
	public function run(): array {
		$switched = is_multisite() && get_current_blog_id() !== get_main_site_id();
		if ( $switched ) {
			switch_to_blog( get_main_site_id() );
		}
		require_once ABSPATH . 'wp-admin/includes/plugin.php';
		$start           = microtime( true );
		$this->deadline  = $start + self::TIME_BUDGET;
		$this->findings  = array();
		$this->truncated = array();
		foreach ( array_keys( self::checks() ) as $check ) {
			try {
				$this->{'check_' . $check}();
			} catch ( \Throwable $e ) {
				/* translators: %s: error message. */
				$this->add( $check, 'notice', __( 'This check could not finish', 'sentinel-shield' ), sprintf( __( 'Error: %s', 'sentinel-shield' ), $e->getMessage() ) );
			}
		}
		if ( $switched ) {
			restore_current_blog();
		}

		$previous = self::report();
		$before   = array();
		foreach ( (array) ( $previous['findings'] ?? array() ) as $finding ) {
			if ( self::is_alert( $finding ) ) {
				$before[ $finding['id'] ] = true;
			}
		}
		$new = array();
		foreach ( $this->findings as $finding ) {
			if ( self::is_alert( $finding ) && ! isset( $before[ $finding['id'] ] ) ) {
				$new[] = (string) $finding['id'];
			}
		}
		$report = array(
			'time'      => time(),
			'duration'  => round( microtime( true ) - $start, 2 ),
			'findings'  => $this->findings,
			'truncated' => $this->truncated,
			'new'       => $new,
		);
		update_site_option( self::REPORT_OPTION, $report );
		return $report;
	}

	/**
	 * Last stored report.
	 *
	 * @return array<string, mixed>|null
	 */
	public static function report(): ?array {
		$report = get_site_option( self::REPORT_OPTION );
		return is_array( $report ) ? $report : null;
	}

	/**
	 * Whether a finding should raise an alert (critical or warning, not approved).
	 *
	 * @param array<string, mixed> $finding Finding.
	 */
	public static function is_alert( array $finding ): bool {
		return in_array( $finding['severity'] ?? '', array( 'critical', 'warning' ), true );
	}

	/**
	 * Approved findings: id => [hash, title, at, by].
	 *
	 * @return array<string, array{hash:string, title:string, at:int, by:int}>
	 */
	public static function baseline(): array {
		$baseline = get_site_option( self::BASELINE_OPTION, array() );
		return is_array( $baseline ) ? $baseline : array();
	}

	/**
	 * Approves a finding from the last report as it is now.
	 *
	 * @param string $id Finding ID.
	 * @param int    $by Acting user.
	 * @return array<string, mixed>|null The finding, or null if it is not in the report or not approvable.
	 */
	public static function approve( string $id, int $by ): ?array {
		foreach ( (array) ( self::report()['findings'] ?? array() ) as $finding ) {
			if ( $finding['id'] === $id && '' !== (string) $finding['hash'] ) {
				$baseline        = self::baseline();
				$baseline[ $id ] = array(
					'hash'  => (string) $finding['hash'],
					'title' => (string) $finding['title'],
					'at'    => time(),
					'by'    => $by,
				);
				update_site_option( self::BASELINE_OPTION, $baseline );
				self::mark_in_report( $id, true );
				return $finding;
			}
		}
		return null;
	}

	/**
	 * Withdraws an approval.
	 *
	 * @param string $id Finding ID.
	 */
	public static function unapprove( string $id ): bool {
		$baseline = self::baseline();
		if ( ! isset( $baseline[ $id ] ) ) {
			return false;
		}
		unset( $baseline[ $id ] );
		update_site_option( self::BASELINE_OPTION, $baseline );
		self::mark_in_report( $id, false );
		return true;
	}

	/**
	 * Malware traits found in PHP code: list of [reason, severity].
	 *
	 * @param string $code Source code.
	 * @return list<array{0:string, 1:string}>
	 */
	public static function signatures( string $code ): array {
		if ( '' === $code ) {
			return array();
		}
		$rules = array(
			array( '/\bSC_[A-Z0-9_]*(?:BEGIN|START|END|AUTO_PREPEND|GUARD|LOADED)/', 'critical', __( 'SC malware marker', 'sentinel-shield' ) ),
			array( '/hyper[-_]?engine[-_]?kit/i', 'critical', __( 'name of the SC malware plugin', 'sentinel-shield' ) ),
			array( '/\b(?:gzinflate|gzuncompress|gzdecode|str_rot13)\s*\(\s*base64_decode\s*\(/i', 'critical', __( 'unpacks a hidden payload', 'sentinel-shield' ) ),
			array( '/\b(?:eval|assert)\s*\(\s*(?:gz|base64_decode|str_rot13|\$)/i', 'critical', __( 'runs decoded or variable code', 'sentinel-shield' ) ),
			array( '/\b(?:shmop_open|shm_attach|shm_get_var)\s*\(/i', 'critical', __( 'stores code in shared memory', 'sentinel-shield' ) ),
			array( '/\beth_(?:call|getStorageAt)\b/', 'critical', __( 'reads commands from a blockchain', 'sentinel-shield' ) ),
			array( '/\b(?:include|require)(?:_once)?\b[^;]{0,200}[\'"\/]\.[\w-]+\.php[0-9]?[\'"]/i', 'critical', __( 'loads a hidden (dot-prefixed) PHP file', 'sentinel-shield' ) ),
			array( '/auto_prepend_file/i', 'warning', __( 'changes the PHP auto-prepend setting', 'sentinel-shield' ) ),
			array( '/[A-Za-z0-9+\/]{4000,}/', 'warning', __( 'contains a large encoded blob', 'sentinel-shield' ) ),
			array( '/(?:\\\\x[0-9a-fA-F]{2}){16,}/', 'warning', __( 'contains heavily escaped strings', 'sentinel-shield' ) ),
		);
		$out   = array();
		foreach ( $rules as [ $pattern, $severity, $reason ] ) {
			if ( preg_match( $pattern, $code ) ) {
				$out[] = array( $reason, $severity );
			}
		}
		if ( preg_match( '/mu-plugins/i', $code ) && preg_match( '/\b(?:file_put_contents|fwrite|copy|rename)\s*\(/i', $code ) ) {
			$out[] = array( __( 'writes files into mu-plugins', 'sentinel-shield' ), 'warning' );
		}
		return $out;
	}

	/**
	 * Highest severity in a list of [reason, severity].
	 *
	 * @param list<array{0:string, 1:string}> $reasons Reasons.
	 * @param string                          $floor   Severity when the list is empty.
	 */
	public static function worst( array $reasons, string $floor ): string {
		$rank = array_flip( self::SEVERITIES );
		$best = $floor;
		foreach ( $reasons as $reason ) {
			if ( $rank[ $reason[1] ] < $rank[ $best ] ) {
				$best = $reason[1];
			}
		}
		return $best;
	}

	/**
	 * Auto-prepend/append settings in effect or written in config files.
	 */
	private function check_prepend(): void {
		$targets = array();
		foreach ( array( 'auto_prepend_file', 'auto_append_file' ) as $ini ) {
			$value = trim( (string) ini_get( $ini ) );
			if ( '' !== $value && 'none' !== strtolower( $value ) ) {
				/* translators: %s: PHP setting name. */
				$targets[ $value ][] = sprintf( __( 'active PHP setting %s', 'sentinel-shield' ), $ini );
			}
		}
		foreach ( $this->config_dirs() as $dir ) {
			foreach ( array( '.user.ini', 'php.ini', '.htaccess' ) as $name ) {
				$file = trailingslashit( $dir ) . $name;
				if ( ! is_readable( $file ) || ! is_file( $file ) ) {
					continue;
				}
				preg_match_all( '/^\s*(?:php_value\s+)?auto_(?:prepend|append)_file\s*=?\s*["\']?([^"\'\r\n;#]+)/mi', $this->read( $file ), $matches );
				foreach ( $matches[1] as $target ) {
					$target = trim( $target );
					if ( '' === $target || 'none' === strtolower( $target ) ) {
						continue;
					}
					if ( ! str_starts_with( $target, '/' ) && ! preg_match( '/^[A-Za-z]:[\\\\\/]/', $target ) ) {
						$target = trailingslashit( $dir ) . $target;
					}
					$targets[ $target ][] = CronInspector::relative( $file );
				}
			}
		}
		foreach ( $targets as $target => $sources ) {
			$exists  = is_file( $target );
			$code    = $exists ? $this->read( $target ) : '';
			$reasons = self::signatures( $code );
			$base    = basename( $target );
			if ( str_starts_with( $base, '.' ) ) {
				$reasons[] = array( __( 'loads a hidden (dot-prefixed) file', 'sentinel-shield' ), 'critical' );
			}
			if ( ! $exists ) {
				$reasons[] = array( __( 'the file it points to is missing, so PHP may fail on every request while the setting is cached', 'sentinel-shield' ), 'warning' );
			}
			$known = $exists && ( 'wordfence-waf.php' === $base || str_contains( $code, 'Wordfence' ) );
			$this->add(
				'prepend',
				self::worst( $reasons, $known ? 'notice' : 'warning' ),
				/* translators: %s: file path. */
				sprintf( __( 'PHP runs %s before every request', 'sentinel-shield' ), CronInspector::relative( $target ) ),
				/* translators: %s: list of places. */
				sprintf( __( 'Set in: %s.', 'sentinel-shield' ), implode( ', ', array_unique( $sources ) ) ) . ' ' . self::reasons_text( $reasons )
					. ( $known ? ' ' . __( 'This looks like the Wordfence firewall loader, which is expected if you use Wordfence.', 'sentinel-shield' ) : '' )
					. ' ' . __( 'To remove a malicious loader safely, first replace the target file with an empty PHP file, then remove the line, then restart PHP: PHP caches this setting, and deleting the file first breaks the whole site.', 'sentinel-shield' ),
				'prepend:' . $target,
				md5( ( $exists ? (string) sha1_file( $target ) : '' ) . '|' . implode( '|', $sources ) )
			);
		}
	}

	/**
	 * Drop-in files in wp-content.
	 */
	private function check_dropins(): void {
		foreach ( array_keys( _get_dropins() ) as $name ) {
			$path = WP_CONTENT_DIR . '/' . $name;
			if ( ! is_file( $path ) ) {
				continue;
			}
			$extra = 'advanced-cache.php' === $name && ! ( defined( 'WP_CACHE' ) && WP_CACHE )
				? ' ' . __( 'WP_CACHE is off, so WordPress does not load this file at the moment.', 'sentinel-shield' )
				: '';
			$this->file_finding( 'dropins', $path, 'notice', __( 'Drop-ins run before every plugin. If you recognize this file (for example from a caching or object cache plugin), approve it and you will be warned if it changes.', 'sentinel-shield' ) . $extra );
		}
	}

	/**
	 * Must-use plugins, including ones that duplicate a regular plugin.
	 */
	private function check_mu_plugins(): void {
		foreach ( (array) glob( WPMU_PLUGIN_DIR . '/*.php' ) as $path ) {
			$path  = (string) $path;
			$slug  = basename( $path, '.php' );
			$extra = is_dir( WP_PLUGIN_DIR . '/' . $slug )
				? array( array( __( 'the same plugin is also installed as a regular plugin, as SC does', 'sentinel-shield' ), 'critical' ) )
				: array();
			$this->file_finding( 'mu_plugins', $path, 'notice', __( 'Must-use plugins always run and cannot be deactivated. Approve the ones you or your host installed.', 'sentinel-shield' ), $extra );
		}
	}

	/**
	 * Plugins removed from the Plugins screen.
	 */
	private function check_hidden_plugins(): void {
		$all    = get_plugins();
		$shown  = (array) apply_filters( 'all_plugins', $all ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Applies core's filter to see what the Plugins screen shows.
		$active = (array) get_option( 'active_plugins', array() );
		if ( is_multisite() ) {
			$active = array_merge( $active, array_keys( (array) get_site_option( 'active_sitewide_plugins', array() ) ) );
		}
		foreach ( array_diff_key( $all, $shown ) as $file => $data ) {
			$path    = WP_PLUGIN_DIR . '/' . $file;
			$reasons = self::signatures( $this->read( $path ) );
			$this->add(
				'hidden_plugins',
				self::worst( $reasons, 'warning' ),
				/* translators: %s: plugin name. */
				sprintf( __( 'Plugin hidden from the Plugins screen: %s', 'sentinel-shield' ), (string) ( $data['Name'] ?? $file ) ),
				/* translators: %s: plugin file. */
				sprintf( __( 'File: wp-content/plugins/%s.', 'sentinel-shield' ), $file ) . ' '
					. ( in_array( $file, $active, true ) ? __( 'It is active.', 'sentinel-shield' ) . ' ' : '' )
					. __( 'Some code removes it from the list (all_plugins filter). Managed hosts sometimes hide their own plugins; otherwise this is how SC hides.', 'sentinel-shield' ) . ' ' . self::reasons_text( $reasons ),
				'plugin:' . $file,
				is_file( $path ) ? (string) sha1_file( $path ) : md5( $file )
			);
		}
		$labels = array(
			'mustuse' => __( 'Must-Use', 'sentinel-shield' ),
			'dropins' => __( 'Drop-ins', 'sentinel-shield' ),
		);
		foreach ( $labels as $type => $label ) {
			if ( false === apply_filters( 'show_advanced_plugins', true, $type ) ) { // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Core filter, see above.
				$this->add(
					'hidden_plugins',
					'warning',
					/* translators: %s: list name. */
					sprintf( __( 'The %s list on the Plugins screen is hidden', 'sentinel-shield' ), $label ),
					__( 'Some code hides this list (show_advanced_plugins filter), so must-use plugins or drop-ins cannot be seen in the admin.', 'sentinel-shield' ),
					'advanced:' . $type,
					md5( 'advanced:' . $type )
				);
			}
		}
	}

	/**
	 * Hidden, unapproved or oddly privileged administrators.
	 */
	private function check_admins(): void {
		$lock = $this->admins->enforced( (bool) $this->settings->get( 'lockdown.admin_lock', false ) );
		foreach ( $this->admins->fixed_report() as $entry ) {
			if ( in_array( $entry['state'], array( 'missing', 'id_mismatch' ), true ) ) {
				$this->add(
					'admins',
					'missing' === $entry['state'] ? 'warning' : 'critical',
					/* translators: %s: list entry. */
					sprintf( __( 'SENTINEL_SHIELD_ADMINS entry "%s" matches no account', 'sentinel-shield' ), $entry['entry'] ),
					'missing' === $entry['state']
						? __( 'No account has this login, so anyone who creates one would become an approved administrator. Remove the entry from wp-config.php, or pin it to a user ID (login#ID).', 'sentinel-shield' )
						/* translators: %d: user ID. */
						: sprintf( __( 'The login now belongs to account ID %d, not the pinned ID, so it is not approved. The original account may have been deleted and the login re-registered.', 'sentinel-shield' ), $entry['user_id'] ),
					'fixed-admin:' . $entry['entry'],
					md5( $entry['entry'] . '|' . $entry['state'] . '|' . $entry['user_id'] )
				);
			}
		}
		foreach ( $this->admins->privileged_users() as $user ) {
			/* translators: 1: login, 2: user ID, 3: email, 4: registration date. */
			$who = sprintf( __( '%1$s (ID %2$d, %3$s, registered %4$s)', 'sentinel-shield' ), $user['login'], $user['id'], $user['email'], $user['registered'] );
			if ( $user['hidden'] ) {
				$this->add(
					'admins',
					'critical',
					/* translators: %s: account description. */
					sprintf( __( 'Administrator hidden from the Users screen: %s', 'sentinel-shield' ), $who ),
					__( 'Some code removes this account from the user list. SC creates its administrator directly in the database and hides it this way. Unless you know why it is hidden, delete it and change all passwords.', 'sentinel-shield' ),
					'admin-hidden:' . $user['id'],
					md5( $user['id'] . '|' . $user['login'] )
				);
			} elseif ( $user['direct_caps'] ) {
				$this->add(
					'admins',
					'warning',
					/* translators: %s: account description. */
					sprintf( __( 'Account with administrator powers but no administrator role: %s', 'sentinel-shield' ), $who ),
					__( 'The account was given admin capabilities directly, which hides it from the Administrator filter on the Users screen.', 'sentinel-shield' ),
					'admin-caps:' . $user['id'],
					md5( $user['id'] . '|' . $user['login'] . '|' . implode( ',', $user['roles'] ) )
				);
			}
			if ( $lock && ! $user['approved'] ) {
				$this->add(
					'admins',
					'warning',
					/* translators: %s: account description. */
					sprintf( __( 'Administrator waiting for approval: %s', 'sentinel-shield' ), $who ),
					$this->admins->is_fixed()
						? __( 'The administrator lock denies this account every admin capability because it is not listed in SENTINEL_SHIELD_ADMINS in wp-config.php.', 'sentinel-shield' )
						: __( 'The administrator lock denies this account every admin capability until it is approved in the Administrators section below.', 'sentinel-shield' ),
					'admin-pending:' . $user['id']
				);
			}
		}
	}

	/**
	 * Database triggers.
	 */
	private function check_triggers(): void {
		global $wpdb;
		$rows = $wpdb->get_results( 'SELECT TRIGGER_NAME AS name, EVENT_MANIPULATION AS ev, EVENT_OBJECT_TABLE AS tbl, ACTION_STATEMENT AS stmt FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA = DATABASE()', ARRAY_A ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Read-only metadata query with no input.
		if ( '' !== $wpdb->last_error ) {
			$this->add( 'triggers', 'notice', __( 'Database triggers could not be read', 'sentinel-shield' ), $wpdb->last_error );
			return;
		}
		$user_tables = array( $wpdb->users, $wpdb->usermeta );
		foreach ( (array) $rows as $row ) {
			$stmt     = (string) $row['stmt'];
			$severity = in_array( $row['tbl'], $user_tables, true ) || preg_match( '/capabilities|administrator|user_pass|user_level/i', $stmt )
				? 'critical'
				: ( str_starts_with( (string) $row['tbl'], $wpdb->base_prefix ) ? 'warning' : 'notice' );
			$this->add(
				'triggers',
				$severity,
				/* translators: 1: trigger name, 2: table. */
				sprintf( __( 'Database trigger %1$s on %2$s', 'sentinel-shield' ), $row['name'], $row['tbl'] ),
				/* translators: 1: SQL operation, 2: statement. */
				sprintf( __( 'Runs on every %1$s. WordPress does not use triggers; triggers on user tables can re-create a deleted administrator. Statement: %2$s', 'sentinel-shield' ), $row['ev'], mb_strimwidth( $stmt, 0, 300, '…' ) ),
				'trigger:' . $row['name'],
				md5( $row['name'] . '|' . $stmt )
			);
		}
	}

	/**
	 * Malware traits in the functions.php of installed themes.
	 */
	private function check_theme(): void {
		$active = array_unique( array( get_template_directory(), get_stylesheet_directory() ) );
		foreach ( wp_get_themes() as $theme ) {
			$dir  = $theme->get_stylesheet_directory();
			$path = $dir . '/functions.php';
			if ( is_file( $path ) ) {
				$this->file_finding( 'theme', $path, '', in_array( $dir, $active, true ) ? __( 'This theme is active.', 'sentinel-shield' ) : __( 'This theme is not active, but its code can still be loaded directly.', 'sentinel-shield' ) );
			}
		}
	}

	/**
	 * Dot-prefixed PHP, random-name shims and ZIP bundles; PHP in uploads.
	 */
	private function check_stray_files(): void {
		$tops = array( untrailingslashit( ABSPATH ), WP_CONTENT_DIR, WP_PLUGIN_DIR, WPMU_PLUGIN_DIR, get_theme_root() );
		foreach ( wp_get_themes() as $theme ) {
			$tops[] = $theme->get_stylesheet_directory();
		}
		foreach ( array_unique( $tops ) as $dir ) {
			foreach ( (array) @scandir( $dir ) as $name ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Unreadable folders are skipped.
				$name = (string) $name;
				$path = $dir . '/' . $name;
				if ( '.' === $name || '..' === $name || ! is_file( $path ) ) {
					continue;
				}
				$this->stray( $path, $name, WP_CONTENT_DIR === $dir );
			}
		}

		$uploads = (string) wp_get_upload_dir()['basedir'];
		if ( ! is_dir( $uploads ) ) {
			return;
		}
		$count = 0;
		$iter  = new \RecursiveIteratorIterator( new \RecursiveDirectoryIterator( $uploads, \FilesystemIterator::SKIP_DOTS ), \RecursiveIteratorIterator::LEAVES_ONLY, \RecursiveIteratorIterator::CATCH_GET_CHILD );
		foreach ( $iter as $file ) {
			if ( ++$count > self::MAX_ENTRIES || microtime( true ) > $this->deadline ) {
				$this->truncated[] = 'stray_files';
				break;
			}
			if ( ! $file instanceof \SplFileInfo || ! $file->isFile() ) {
				continue;
			}
			$name = $file->getFilename();
			$path = $file->getPathname();
			if ( preg_match( '/\.(php[0-9]?|phtml|phar|pht)$/i', $name ) ) {
				if ( 'index.php' === strtolower( $name ) && $file->getSize() <= 200 ) {
					continue; // "Silence is golden" placeholders.
				}
				if ( str_starts_with( $name, '.' ) ) {
					$this->stray( $path, $name, false );
				} else {
					$this->file_finding( 'stray_files', $path, 'warning', __( 'PHP files do not belong in uploads; this is where web shells are usually dropped. A few plugins keep generated PHP here; approve it if you know which one.', 'sentinel-shield' ) );
				}
			} elseif ( '.user.ini' === $name || 'php.ini' === $name ) {
				$this->file_finding( 'stray_files', $path, 'warning', __( 'A PHP settings file inside uploads can switch on an auto-prepend loader for that folder.', 'sentinel-shield' ) );
			} elseif ( preg_match( '/^[0-9a-f]{8,}\.zip$/i', $name ) ) {
				$this->stray( $path, $name, false );
			}
		}
	}

	/**
	 * Classifies one file found at a top level (or a hidden/ZIP file in uploads).
	 *
	 * @param string $path       Path.
	 * @param string $name       File name.
	 * @param bool   $wp_content Whether it sits directly in wp-content.
	 */
	private function stray( string $path, string $name, bool $wp_content ): void {
		if ( preg_match( '/^\..+\.(php[0-9]?|phtml|phar)$/i', $name ) ) {
			$this->file_finding( 'stray_files', $path, 'critical', __( 'Hidden (dot-prefixed) PHP file. SC loads its first stage from a file like this.', 'sentinel-shield' ) );
		} elseif ( $wp_content && preg_match( '/^[0-9a-f]{8,}\.php$/i', $name ) ) {
			$this->file_finding( 'stray_files', $path, 'warning', __( 'Randomly named PHP file in wp-content, like the SC shim that loads its hidden loader.', 'sentinel-shield' ) );
		} elseif ( preg_match( '/^[0-9a-f]{8,}\.zip$/i', $name ) ) {
			$this->add(
				'stray_files',
				'warning',
				/* translators: %s: file path. */
				sprintf( __( 'Randomly named ZIP file: %s', 'sentinel-shield' ), CronInspector::relative( $path ) ),
				__( 'SC keeps a ZIP restore bundle with a random hex name in wp-content, uploads or a theme folder.', 'sentinel-shield' ),
				'file:' . $path,
				(string) sha1_file( $path )
			);
		}
	}

	/**
	 * Large encoded option values and sc_ control options.
	 */
	private function check_options(): void {
		global $wpdb;
		$rows = $wpdb->get_results( $wpdb->prepare( 'SELECT option_name, LENGTH(option_value) AS len, LEFT(option_value, 4096) AS head FROM %i WHERE LENGTH(option_value) > %d AND option_value NOT LIKE %s AND option_value NOT LIKE %s AND option_value NOT LIKE %s AND option_value NOT LIKE %s LIMIT 200', $wpdb->options, 20000, 'a:%', 'O:%', '{%', '[%' ), ARRAY_A ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Bulk read-only scan.
		foreach ( (array) $rows as $row ) {
			$head = preg_replace( '/\s+/', '', (string) $row['head'] );
			if ( strlen( (string) $head ) < 1000 || ! preg_match( '/^[A-Za-z0-9+\/=_-]+$/', (string) $head ) ) {
				continue;
			}
			$bin        = (string) base64_decode( strtr( substr( (string) $head, 0, 2000 ), '-_', '+/' ), false ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- Inspecting a suspected payload, not running it.
			$compressed = str_starts_with( $bin, "\x1f\x8b" ) || ( '' !== $bin && "\x78" === $bin[0] ) || str_contains( $bin, '<?php' );
			$this->add(
				'options',
				$compressed ? 'critical' : 'warning',
				/* translators: 1: option name, 2: size. */
				sprintf( __( 'Encoded data in option "%1$s" (%2$s)', 'sentinel-shield' ), $row['option_name'], size_format( (int) $row['len'] ) ),
				( $compressed ? __( 'It decodes to compressed data or PHP code.', 'sentinel-shield' ) : __( 'It is one long base64 string.', 'sentinel-shield' ) ) . ' '
					. __( 'SC keeps a full compressed copy of itself in a randomly named option and restores its files from it. Some plugins store images or licence data this way; approve it if you recognize the plugin.', 'sentinel-shield' ),
				'option:' . $row['option_name'],
				md5( $row['option_name'] . '|' . $row['len'] . '|' . md5( (string) $row['head'] ) )
			);
		}

		$like  = $wpdb->esc_like( 'sc_' ) . '%';
		$names = (array) $wpdb->get_col( $wpdb->prepare( 'SELECT option_name FROM %i WHERE option_name LIKE %s OR option_name LIKE %s OR option_name LIKE %s ORDER BY option_name LIMIT 50', $wpdb->options, $like, $wpdb->esc_like( '_transient_sc_' ) . '%', $wpdb->esc_like( '_site_transient_sc_' ) . '%' ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Read-only scan.
		if ( is_multisite() ) {
			$names = array_merge( $names, (array) $wpdb->get_col( $wpdb->prepare( 'SELECT meta_key FROM %i WHERE meta_key LIKE %s OR meta_key LIKE %s LIMIT 50', $wpdb->sitemeta, $like, $wpdb->esc_like( '_site_transient_sc_' ) . '%' ) ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Read-only scan.
		}
		if ( $names ) {
			$this->add(
				'options',
				'warning',
				/* translators: %s: option names. */
				sprintf( __( 'Options with the sc_ prefix: %s', 'sentinel-shield' ), implode( ', ', array_slice( $names, 0, 10 ) ) . ( count( $names ) > 10 ? ' …' : '' ) ),
				__( 'SC keeps its control data in sc_ options and transients. A legitimate plugin may use the same prefix; approve if you recognize it.', 'sentinel-shield' ),
				'sc-options',
				md5( implode( '|', $names ) )
			);
		}
	}

	/**
	 * Scheduled tasks that run code from odd places or look randomly named.
	 */
	private function check_cron(): void {
		foreach ( CronInspector::events() as $event ) {
			$bad = array();
			foreach ( $event['callbacks'] as $callback ) {
				if ( 'warning' === $callback['flag'] || self::is_dropin_file( (string) $callback['file'] ) ) {
					$bad[] = $callback['name'] . ' (' . ( '' !== $callback['file'] ? $callback['file'] : $callback['source'] ) . ')';
				}
			}
			$key  = 'cron:' . $event['hook'] . '|' . $event['sig'];
			$hash = md5( $key . '|' . implode( '|', array_column( $event['callbacks'], 'file' ) ) );
			if ( $bad ) {
				$this->add(
					'cron',
					'critical',
					/* translators: %s: hook name. */
					sprintf( __( 'Scheduled task %s runs code from an unusual place', 'sentinel-shield' ), $event['hook'] ),
					/* translators: %s: callbacks. */
					sprintf( __( 'Code: %s. Legitimate plugins do not run scheduled code from uploads, eval() or drop-ins. Pause it on the Scheduled Tasks page.', 'sentinel-shield' ), implode( '; ', $bad ) ),
					$key,
					$hash
				);
			} elseif ( ! $event['callbacks'] && self::looks_random( (string) $event['hook'] ) ) {
				$this->add(
					'cron',
					'warning',
					/* translators: %s: hook name. */
					sprintf( __( 'Randomly named scheduled task with no visible code: %s', 'sentinel-shield' ), $event['hook'] ),
					__( 'SC schedules tasks with random names. Its code may only load while WP-Cron runs. Pause it on the Scheduled Tasks page if you do not recognize it.', 'sentinel-shield' ),
					$key,
					$hash
				);
			}
		}
	}

	/**
	 * Code on login and admin-hiding hooks from must-use plugins, drop-ins, uploads or eval.
	 */
	private function check_hooks(): void {
		global $wp_filter;
		$login = __( 'Code here sees passwords and login cookies; SC uses such hooks to capture logins.', 'sentinel-shield' );
		$hide  = __( 'Code here can hide plugins or users from the admin screens, as SC does.', 'sentinel-shield' );
		$watch = array(
			'authenticate'                  => $login,
			'wp_authenticate'               => $login,
			'wp_authenticate_user'          => $login,
			'wp_login'                      => $login,
			'check_password'                => $login,
			'set_auth_cookie'               => $login,
			'set_logged_in_cookie'          => $login,
			'auth_cookie_valid'             => $login,
			'all_plugins'                   => $hide,
			'pre_user_query'                => $hide,
			'users_list_table_query_args'   => $hide,
			'views_users'                   => $hide,
			'pre_count_users'               => $hide,
			'show_advanced_plugins'         => $hide,
			'site_transient_update_plugins' => $hide,
		);
		foreach ( $watch as $hook => $why ) {
			if ( ! isset( $wp_filter[ $hook ] ) || ! $wp_filter[ $hook ] instanceof \WP_Hook ) {
				continue;
			}
			foreach ( $wp_filter[ $hook ]->callbacks as $callbacks ) {
				foreach ( $callbacks as $callback ) {
					$info = CronInspector::describe( $callback['function'] );
					$file = (string) $info['file'];
					if ( self::is_dropin_file( $file ) || 'warning' === $info['flag'] ) {
						$severity = 'warning' === $info['flag'] ? 'critical' : 'warning';
					} elseif ( str_starts_with( $file, 'wp-content/mu-plugins/' ) ) {
						$severity = 'notice';
					} else {
						continue;
					}
					$abs = '' !== $file && ! str_starts_with( $file, '/' ) ? ABSPATH . $file : $file;
					$this->add(
						'hooks',
						$severity,
						/* translators: 1: callback, 2: hook. */
						sprintf( __( '%1$s is attached to %2$s', 'sentinel-shield' ), $info['name'], $hook ),
						/* translators: 1: file, 2: line, 3: origin, 4: explanation. */
						sprintf( __( 'Defined in %1$s line %2$d (%3$s). %4$s', 'sentinel-shield' ), '' !== $file ? $file : '?', $info['line'], $info['source'], $why ),
						'hook:' . $hook . '|' . $info['name'] . '|' . $file,
						md5( $hook . '|' . $info['name'] . '|' . ( '' !== $abs && is_file( $abs ) ? (string) sha1_file( $abs ) : $file ) )
					);
				}
			}
		}
	}

	/**
	 * Whether PHP can use System V shared memory.
	 */
	private function check_shm(): void {
		$available = array_values( array_filter( array( 'shmop', 'sysvshm' ), 'extension_loaded' ) );
		if ( ! $available ) {
			return;
		}
		$this->add(
			'shm',
			'notice',
			/* translators: %s: PHP extensions. */
			sprintf( __( 'PHP can use System V shared memory (%s)', 'sentinel-shield' ), implode( ', ', $available ) ),
			__( 'A plugin cannot list shared memory segments. If nothing on this site needs these extensions, ask your host to disable them. After a cleanup, restart PHP and have the host check "ipcs -m" for segments owned by your account, because SC can restore itself from memory.', 'sentinel-shield' ),
			'shm',
			md5( implode( ',', $available ) )
		);
	}

	/**
	 * Blocked blockchain requests, or a hint to turn blocking on.
	 */
	private function check_outbound(): void {
		$blocked = $this->events->count_since( array( 'lockdown_outbound' ), time() - 7 * DAY_IN_SECONDS );
		if ( $blocked > 0 ) {
			$this->add(
				'outbound',
				'critical',
				/* translators: %d: count. */
				sprintf( _n( 'Blocked %d attempt to contact a blockchain gateway in the last 7 days', 'Blocked %d attempts to contact blockchain gateways in the last 7 days', $blocked, 'sentinel-shield' ), $blocked ),
				__( 'SC reads its commands from a smart contract this way. The Events log shows which URL was requested.', 'sentinel-shield' ),
				'outbound-blocked'
			);
		} elseif ( ! $this->settings->get( 'lockdown.block_chain_rpc', false ) ) {
			$this->add(
				'outbound',
				'notice',
				__( 'Requests to blockchain gateways are not blocked', 'sentinel-shield' ),
				__( 'Turn on "Block blockchain command channels" on the Settings → Malware Lockdown tab.', 'sentinel-shield' ),
				'outbound-off'
			);
		}
	}

	/**
	 * Adds a finding for a file, graded by its malware traits.
	 *
	 * @param string                          $check  Check slug.
	 * @param string                          $path   Absolute path.
	 * @param string                          $clean  Severity when no traits are found ('' to skip clean files).
	 * @param string                          $detail Explanation.
	 * @param list<array{0:string, 1:string}> $extra  Additional reasons.
	 */
	private function file_finding( string $check, string $path, string $clean, string $detail, array $extra = array() ): void {
		$reasons = array_merge( self::signatures( $this->read( $path ) ), $extra );
		if ( ! $reasons && '' === $clean ) {
			return;
		}
		$rel = CronInspector::relative( $path );
		$this->add(
			$check,
			self::worst( $reasons, '' === $clean ? 'notice' : $clean ),
			$reasons
				/* translators: %s: file path. */
				? sprintf( __( 'Suspicious code in %s', 'sentinel-shield' ), $rel )
				/* translators: %s: file path. */
				: sprintf( __( '%s: not reviewed yet', 'sentinel-shield' ), $rel ),
			trim( $detail . ' ' . self::reasons_text( $reasons ) ),
			'file:' . $path,
			(string) sha1_file( $path )
		);
	}

	/**
	 * Records a finding; approved ones (same hash as when approved) become "ok".
	 *
	 * @param string $check    Check slug.
	 * @param string $severity critical|warning|notice.
	 * @param string $title    Short title.
	 * @param string $detail   Explanation.
	 * @param string $key      Stable identity (defaults to the title).
	 * @param string $hash     Content fingerprint; '' means it cannot be approved.
	 */
	private function add( string $check, string $severity, string $title, string $detail, string $key = '', string $hash = '' ): void {
		$id = md5( $check . '|' . ( '' === $key ? $title : $key ) );
		if ( count( array_filter( $this->findings, static fn( array $f ): bool => $f['check'] === $check ) ) >= self::MAX_PER_CHECK ) {
			$this->truncated[] = $check;
			return;
		}
		$approved         = '' !== $hash && ( self::baseline()[ $id ]['hash'] ?? null ) === $hash;
		$this->findings[] = array(
			'id'       => $id,
			'check'    => $check,
			'severity' => $approved ? 'ok' : $severity,
			'original' => $severity,
			'approved' => $approved,
			'title'    => $title,
			'detail'   => $detail,
			'hash'     => $hash,
		);
	}

	/**
	 * Updates the approved flag of a finding in the stored report.
	 *
	 * @param string $id       Finding ID.
	 * @param bool   $approved New state.
	 */
	private static function mark_in_report( string $id, bool $approved ): void {
		$report = self::report();
		if ( null === $report ) {
			return;
		}
		foreach ( $report['findings'] as &$finding ) {
			if ( $finding['id'] === $id ) {
				$finding['approved'] = $approved;
				$finding['severity'] = $approved ? 'ok' : $finding['original'];
			}
		}
		unset( $finding );
		update_site_option( self::REPORT_OPTION, $report );
	}

	/**
	 * Reasons as a sentence.
	 *
	 * @param list<array{0:string, 1:string}> $reasons Reasons.
	 */
	private static function reasons_text( array $reasons ): string {
		if ( ! $reasons ) {
			return '';
		}
		/* translators: %s: list of findings. */
		return sprintf( __( 'Found: %s.', 'sentinel-shield' ), implode( '; ', array_unique( array_column( $reasons, 0 ) ) ) );
	}

	/**
	 * Whether a (relative or absolute) file is directly in wp-content, i.e. a drop-in.
	 *
	 * @param string $file File path.
	 */
	private static function is_dropin_file( string $file ): bool {
		if ( '' === $file ) {
			return false;
		}
		$abs = str_starts_with( $file, '/' ) ? $file : ABSPATH . $file;
		return wp_normalize_path( dirname( $abs ) ) === wp_normalize_path( WP_CONTENT_DIR );
	}

	/**
	 * Whether a hook name looks machine-generated.
	 *
	 * @param string $hook Hook name.
	 */
	public static function looks_random( string $hook ): bool {
		if ( preg_match( '/^[a-f0-9]{8,}$/i', $hook ) ) {
			return true;
		}
		return (bool) preg_match( '/^[a-z0-9]{10,}$/i', $hook ) && preg_match( '/\d/', $hook ) && preg_match( '/[a-z]/i', $hook ) && ! preg_match( '/[aeiou]{2}|[^aeiou\d]{2}[aeiou]/i', $hook );
	}

	/**
	 * Folders whose PHP config files are checked for auto-prepend lines.
	 *
	 * @return list<string>
	 */
	private function config_dirs(): array {
		$dirs = array( untrailingslashit( ABSPATH ), ABSPATH . 'wp-admin', ABSPATH . WPINC, WP_CONTENT_DIR, WP_PLUGIN_DIR, WPMU_PLUGIN_DIR, get_theme_root(), (string) wp_get_upload_dir()['basedir'] );
		return array_values( array_unique( array_filter( $dirs, 'is_dir' ) ) );
	}

	/**
	 * Reads up to MAX_READ bytes of a file.
	 *
	 * @param string $path Path.
	 */
	private function read( string $path ): string {
		if ( ! is_file( $path ) || ! is_readable( $path ) ) {
			return '';
		}
		return (string) file_get_contents( $path, false, null, 0, self::MAX_READ ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file inspection.
	}
}
