<?php
/**
 * Read-only scan for the persistence points used by the SC WordPress malware.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Lockdown;

use SentinelShield\Cron\CronInspector;
use SentinelShield\Firewall\EarlyGate;
use SentinelShield\Repository\EventRepository;
use SentinelShield\Settings;
use SentinelShield\Support\FileWalk;

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
	public const UPLOADS_STATE   = 'sentinel_shield_scan_uploads';

	public const SEVERITIES = array( 'critical', 'warning', 'notice', 'ok' );

	private const MAX_ENTRIES   = 20000;
	private const MAX_READ      = 2097152;
	private const MAX_PER_CHECK = 100;
	private const TIME_BUDGET   = 20.0;
	private const MIN_PROGRESS  = 500;

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
	 * Files examined per run, with those read only partly or not at all.
	 *
	 * @var array{read:int, partial:list<string>, unreadable:list<string>}
	 */
	private array $coverage = array(
		'read'       => 0,
		'partial'    => array(),
		'unreadable' => array(),
	);

	/**
	 * Progress of the uploads walk, which can span several runs.
	 *
	 * @var array<string, mixed>
	 */
	private array $uploads = array();

	/**
	 * Whether findings are being added by the uploads walk.
	 *
	 * @var bool
	 */
	private bool $in_uploads = false;

	/**
	 * Files the uploads walk may visit per run (0 = no limit).
	 *
	 * @var int
	 */
	private int $entry_limit = self::MAX_ENTRIES;

	/**
	 * Constructor.
	 *
	 * @param AdminRegistry   $admins   Administrator registry.
	 * @param EventRepository $events   Event log.
	 * @param Settings        $settings Settings.
	 * @param int|null        $per_run  Uploads files per run (default MAX_ENTRIES).
	 */
	public function __construct( private AdminRegistry $admins, private EventRepository $events, private Settings $settings, private ?int $per_run = null ) {}

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
			'advisories'     => array( __( 'Recent incidents', 'sentinel-shield' ), __( 'Traces of incidents exploited against WordPress sites in October 2026: the Rank Math PRO 3.0.123 backdoor, backdoor plugins installed through stolen UpdraftCentral keys, and the PHP2Shell flaws in PHP.', 'sentinel-shield' ) ),
		);
	}

	/**
	 * Runs every check and stores the report.
	 *
	 * The uploads folder can hold more files than one run should read; its walk
	 * keeps its position and continues on the next run ("complete" is false
	 * until it reaches the end), so every file is eventually checked. Findings
	 * from earlier parts of the walk are carried into each report.
	 *
	 * @param bool $unbounded No time or entry limit (WP-CLI).
	 * @return array{time:int, duration:float, findings:list<array<string, mixed>>, truncated:list<string>, new:list<string>, complete:bool, coverage:array<string, mixed>}
	 */
	public function run( bool $unbounded = false ): array {
		$switched = is_multisite() && get_current_blog_id() !== get_main_site_id();
		if ( $switched ) {
			switch_to_blog( get_main_site_id() );
		}
		require_once ABSPATH . 'wp-admin/includes/plugin.php';
		$start             = microtime( true );
		$this->deadline    = $unbounded ? INF : $start + self::TIME_BUDGET;
		$this->entry_limit = $unbounded ? 0 : ( $this->per_run ?? self::MAX_ENTRIES );
		$this->findings    = array();
		$this->truncated   = array();
		$this->uploads     = array();
		$this->coverage    = array(
			'read'       => 0,
			'partial'    => array(),
			'unreadable' => array(),
		);
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
			'truncated' => array_values( array_unique( $this->truncated ) ),
			'new'       => $new,
			'complete'  => ! empty( $this->uploads['done'] ) || array() === $this->uploads,
			'coverage'  => $this->coverage + array( 'uploads' => $this->uploads ),
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
		$all = array_merge( (array) ( self::report()['findings'] ?? array() ), (array) ( FileIntegrity::report()['findings'] ?? array() ) );
		foreach ( $all as $finding ) {
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
		$rules = array_merge( $rules, Advisories::code_markers() );
		$out   = array();
		foreach ( $rules as [ $pattern, $severity, $reason ] ) {
			if ( preg_match( $pattern, $code ) ) {
				$out[] = array( $reason, $severity );
			}
		}
		if ( preg_match( '/mu-plugins/i', $code ) && preg_match( '/\b(?:file_put_contents|fwrite|copy|rename)\s*\(/i', $code ) ) {
			$out[] = array( __( 'writes files into mu-plugins', 'sentinel-shield' ), 'warning' );
		}
		if ( preg_match( '/\bbase64_decode\s*\(/i', $code ) && preg_match( '/\bord\s*\([^;]{0,120}\^|\^\s*ord\s*\(/i', $code ) ) {
			$out[] = array( __( 'XOR-decodes a base64 payload', 'sentinel-shield' ), 'warning' );
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
			if ( EarlyGate::is_own_gate( $target ) && self::own_file_intact( EarlyGate::gate_file() ) ) {
				continue; // Sentinel Shield's own early firewall, unchanged.
			}
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
				md5( ( $exists ? self::fingerprint( $target ) : '' ) . '|' . implode( '|', $sources ) )
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
			$path = (string) $path;
			if ( EarlyGate::is_own_loader( $path ) ) {
				continue; // Sentinel Shield's own early firewall loader, exactly as it writes it.
			}
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
				is_file( $path ) ? self::fingerprint( $path ) : md5( $file )
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
			delete_site_option( self::UPLOADS_STATE );
			return;
		}
		$state = get_site_option( self::UPLOADS_STATE );
		$state = is_array( $state ) ? $state : array(
			'cursor'  => '',
			'files'   => 0,
			'started' => time(),
			'carried' => array(),
		);
		// Findings from earlier parts of this walk, re-graded against current approvals.
		$baseline = self::baseline();
		foreach ( (array) $state['carried'] as $finding ) {
			$approved            = '' !== (string) $finding['hash'] && ( $baseline[ $finding['id'] ]['hash'] ?? null ) === $finding['hash'];
			$finding['approved'] = $approved;
			$finding['severity'] = $approved ? 'ok' : $finding['original'];
			$this->findings[]    = $finding;
		}
		$walk             = new FileWalk( $uploads );
		$limit            = $this->entry_limit;
		$this->in_uploads = true;
		try {
			$done = $walk->run(
				(string) $state['cursor'],
				function ( string $path, string $rel ): void {
					$this->upload_file( $path, basename( $rel ) );
				},
				// At least MIN_PROGRESS files per run, so the walk always moves on.
				fn(): bool => ( $limit > 0 && $walk->files >= $limit ) || ( $walk->files >= self::MIN_PROGRESS && microtime( true ) > $this->deadline )
			);
		} finally {
			$this->in_uploads = false;
		}
		$files         = (int) $state['files'] + $walk->files;
		$this->uploads = array(
			'done'       => $done,
			'files'      => $files,
			'started'    => (int) $state['started'],
			'cursor'     => $done ? '' : $walk->cursor,
			'links'      => array_slice( $walk->links, 0, 20 ),
			'unreadable' => array_slice( $walk->unreadable, 0, 20 ),
		);
		if ( $done ) {
			delete_site_option( self::UPLOADS_STATE );
			return;
		}
		update_site_option(
			self::UPLOADS_STATE,
			array(
				'cursor'  => $walk->cursor,
				'files'   => $files,
				'started' => (int) $state['started'],
				'carried' => array_values( array_filter( $this->findings, static fn( array $f ): bool => ! empty( $f['uploads'] ) ) ),
			)
		);
	}

	/**
	 * Classifies one file in uploads.
	 *
	 * @param string $path Absolute path.
	 * @param string $name File name.
	 */
	private function upload_file( string $path, string $name ): void {
		if ( preg_match( '/\.(php[0-9]?|phtml|phar|pht)$/i', $name ) ) {
			if ( 'index.php' === strtolower( $name ) && (int) @filesize( $path ) <= 200 ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Vanished file: treated as empty.
				return; // "Silence is golden" placeholders.
			}
			if ( str_starts_with( $name, '.' ) ) {
				$this->stray( $path, $name, false );
			} else {
				$this->file_finding( 'stray_files', $path, 'warning', __( 'PHP files do not belong in uploads; this is where web shells are usually dropped. A few plugins keep generated PHP here; approve it if you know which one.', 'sentinel-shield' ) );
			}
		} elseif ( '.user.ini' === $name || 'php.ini' === $name ) {
			$this->file_finding( 'stray_files', $path, 'warning', __( 'A PHP settings file inside uploads can switch on an auto-prepend loader for that folder.', 'sentinel-shield' ) );
		} elseif ( preg_match( '/^[0-9a-f]{8,}\.zip$/i', $name ) || str_ends_with( strtolower( $name ), '.cache' ) ) {
			$this->stray( $path, $name, false );
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
		} elseif ( str_ends_with( strtolower( $name ), '.cache' ) ) {
			$this->php_cache_file( $path );
		} elseif ( preg_match( '/^[0-9a-f]{8,}\.zip$/i', $name ) ) {
			$this->add(
				'stray_files',
				'warning',
				/* translators: %s: file path. */
				sprintf( __( 'Randomly named ZIP file: %s', 'sentinel-shield' ), CronInspector::relative( $path ) ),
				__( 'SC keeps a ZIP restore bundle with a random hex name in wp-content, uploads or a theme folder.', 'sentinel-shield' ),
				'file:' . $path,
				self::fingerprint( $path )
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
			'authenticate'                => $login,
			'wp_authenticate'             => $login,
			'wp_authenticate_user'        => $login,
			'wp_login'                    => $login,
			'check_password'              => $login,
			'set_auth_cookie'             => $login,
			'set_logged_in_cookie'        => $login,
			'auth_cookie_valid'           => $login,
			'all_plugins'                 => $hide,
			'pre_user_query'              => $hide,
			'users_list_table_query_args' => $hide,
			'views_users'                 => $hide,
			'pre_count_users'             => $hide,
			'show_advanced_plugins'       => $hide,
		);
		// Watched, not used: malware hides itself from the update list here. Built
		// from parts so update-checker scanners do not mistake it for an updater.
		$watch[ 'site_transient_' . 'update_plugins' ] = $hide; // phpcs:ignore Generic.Strings.UnnecessaryStringConcat.Found -- See above.

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
						md5( $hook . '|' . $info['name'] . '|' . ( '' !== $abs && is_file( $abs ) ? self::fingerprint( $abs ) : $file ) )
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
	 * Traces of the incidents listed in Advisories.
	 */
	private function check_advisories(): void {
		$plugins = get_plugins();
		$traces  = $this->advisory_rankmath( $plugins );
		$this->advisory_updraft( $plugins );
		$this->advisory_accounts();
		$this->advisory_ssh();
		$this->advisory_php();
		if ( $traces ) {
			$this->advisory_deep_search();
		}
	}

	/**
	 * Rank Math PRO 3.0.123 and what its backdoor leaves behind.
	 *
	 * @param array<string, array<string, mixed>> $plugins Installed plugins.
	 * @return bool Whether there are signs the backdoor ran here.
	 */
	private function advisory_rankmath( array $plugins ): bool {
		global $wpdb;
		$traces = false;
		foreach ( $plugins as $file => $data ) {
			$is_pro = 'rank-math-pro.php' === basename( $file ) || (bool) preg_match( '/^Rank Math (?:SEO )?PRO$/i', trim( (string) ( $data['Name'] ?? '' ) ) );
			if ( ! $is_pro || '3.0.123' !== (string) ( $data['Version'] ?? '' ) ) {
				continue;
			}
			$written   = (int) @filemtime( WP_PLUGIN_DIR . '/' . $file ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Vanished file: treated as unknown.
			$in_window = 0 === $written || $written >= Advisories::RANKMATH_WINDOW[0];
			$traces    = $traces || $in_window;
			$this->add(
				'advisories',
				$in_window ? 'critical' : 'warning',
				/* translators: %s: plugin file. */
				sprintf( __( 'Rank Math PRO 3.0.123 is installed (%s)', 'sentinel-shield' ), $file ),
				( $in_window
					/* translators: %s: date and time (UTC). */
					? sprintf( __( 'Its files were written on %s, after the backdoored build appeared (20:02 UTC on 15 October 2026). Treat the site as compromised: restore a backup from before then if you can; otherwise delete the whole plugin folder (deactivating is not enough), deal with every other finding in this list, change every password and key the site holds, and install 3.0.124 from your rankmath.com account.', 'sentinel-shield' ), $written ? gmdate( 'Y-m-d H:i', $written ) . ' UTC' : '?' )
					/* translators: %s: date and time (UTC). */
					: sprintf( __( 'Its files were written on %s, before the backdoored build appeared, so this copy is probably clean. Update to 3.0.124 from your rankmath.com account.', 'sentinel-shield' ), gmdate( 'Y-m-d H:i', $written ) . ' UTC' ) )
					. ' CVE-2026-111862.',
				'rankmath:' . $file,
				md5( $file . '|' . $written )
			);
		}

		$names = Advisories::RANKMATH_OPTIONS;
		$found = (array) $wpdb->get_col( $wpdb->prepare( 'SELECT option_name FROM %i WHERE option_name IN (' . implode( ',', array_fill( 0, count( $names ), '%s' ) ) . ')', $wpdb->options, ...$names ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber -- Read-only scan; the placeholders are generated.
		if ( $found ) {
			$traces = true;
			$this->add(
				'advisories',
				'critical',
				/* translators: %s: option names. */
				sprintf( __( 'Options written by the Rank Math PRO backdoor: %s', 'sentinel-shield' ), implode( ', ', $found ) ),
				__( 'These option names belong to the backdoor shipped in Rank Math PRO 3.0.123 (CVE-2026-111862). Delete them after removing the rank-math-pro folder, and look for the other traces listed here: administrators named wpsupport_…, PHP in .cache files, wp-includes/class-wp-cache-util.php, changed .htaccess files, scheduled tasks and SSH keys.', 'sentinel-shield' ),
				'rankmath-options'
			);
		}

		$fake = ABSPATH . WPINC . '/' . Advisories::RANKMATH_FAKE_CORE;
		if ( is_file( $fake ) ) {
			$traces = true;
			$this->file_finding( 'advisories', $fake, 'critical', __( 'WordPress has no such core file. The Rank Math PRO backdoor plants it as a disguised copy of itself.', 'sentinel-shield' ) );
		}

		foreach ( $this->config_dirs() as $dir ) {
			$file = $dir . '/.htaccess';
			if ( ! is_file( $file ) ) {
				continue;
			}
			$text = $this->read( $file );
			if ( preg_match( '/^[^\n#]*\b(?:AddHandler|AddType)\b[^\n#]*php[^\n#]*\.cache\b/mi', $text ) || preg_match( '/<Files(?:Match)?\s[^>]*cache[^>]*>(?:(?!<\/Files).){0,500}?\b(?:SetHandler|ForceType|AddHandler)\b[^\n]*php/is', $text ) ) {
				$traces = true;
				$this->add(
					'advisories',
					'critical',
					/* translators: %s: file path. */
					sprintf( __( '%s makes .cache files run as PHP', 'sentinel-shield' ), CronInspector::relative( $file ) ),
					__( 'The Rank Math PRO backdoor adds this rule so the PHP it hides in .cache files can be requested over the web. Remove the rule and the .cache files with PHP in them.', 'sentinel-shield' ),
					'htaccess-cache:' . $file,
					self::fingerprint( $file )
				);
			}
		}
		return $traces;
	}

	/**
	 * Classifies a .cache file: PHP code in one is how the Rank Math PRO backdoor hides.
	 *
	 * @param string $path Path.
	 */
	private function php_cache_file( string $path ): void {
		if ( ! preg_match( '/<\?(?:php\b|=)/i', $this->read( $path ) ) ) {
			return;
		}
		$this->file_finding( 'advisories', $path, 'warning', __( 'This .cache file contains PHP code. The Rank Math PRO backdoor hides PHP in .cache files and changes .htaccess so they run; caching plugins do not need PHP in them.', 'sentinel-shield' ) );
	}

	/**
	 * Searches plugins, must-use plugins and themes for the Rank Math PRO
	 * backdoor's markers, which it copies into other plugins and themes. Only
	 * run when other traces were found; WP-CLI runs it to the end.
	 */
	private function advisory_deep_search(): void {
		$own   = wp_normalize_path( dirname( SENTINEL_SHIELD_FILE ) );
		$rules = array_slice( Advisories::code_markers(), 0, 3 );
		$hits  = 0;
		foreach ( array_unique( array( WP_PLUGIN_DIR, WPMU_PLUGIN_DIR, get_theme_root() ) ) as $root ) {
			if ( ! is_dir( $root ) ) {
				continue;
			}
			$skip = str_starts_with( $own, wp_normalize_path( $root ) . '/' ) ? array( substr( $own, strlen( wp_normalize_path( $root ) ) + 1 ) ) : array();
			$walk = new FileWalk( $root, $skip );
			$done = $walk->run(
				'',
				function ( string $path, string $rel ) use ( $rules, &$hits ): void {
					if ( ! preg_match( '/\.(?:php[0-9]?|phtml|cache|inc)$/i', $rel ) ) {
						return;
					}
					$code = $this->read( $path );
					foreach ( $rules as [ $pattern, , $reason ] ) {
						if ( preg_match( $pattern, $code ) ) {
							++$hits;
							$this->add(
								'advisories',
								'critical',
								/* translators: %s: file path. */
								sprintf( __( 'Rank Math PRO backdoor code in %s', 'sentinel-shield' ), CronInspector::relative( $path ) ),
								/* translators: %s: what was found. */
								sprintf( __( 'Found: %s. The backdoor copies itself into other plugins, themes (inc/, includes/, lib/) and must-use plugins. Replace the affected plugin or theme with a fresh copy.', 'sentinel-shield' ), $reason ),
								'file:' . $path,
								self::fingerprint( $path )
							);
							return;
						}
					}
				},
				fn(): bool => microtime( true ) > $this->deadline
			);
			if ( ! $done ) {
				$this->truncated[] = 'advisories';
				break;
			}
		}
	}

	/**
	 * UpdraftPlus versions and keys exposed by the UpdraftCentral incident, and its backdoor plugins.
	 *
	 * @param array<string, array<string, mixed>> $plugins Installed plugins.
	 */
	private function advisory_updraft( array $plugins ): void {
		foreach ( $plugins as $file => $data ) {
			$code    = $this->read( WP_PLUGIN_DIR . '/' . $file );
			$markers = array_values( array_filter( Advisories::code_markers(), static fn( array $m ): bool => 'critical' === $m[1] && (bool) preg_match( $m[0], $code ) ) );
			$named   = in_array( strtolower( trim( (string) ( $data['Name'] ?? '' ) ) ), array_map( 'strtolower', Advisories::UPDRAFT_PLUGIN_NAMES ), true );
			if ( $markers || $named ) {
				$this->add(
					'advisories',
					$markers ? 'critical' : 'warning',
					/* translators: %s: plugin name. */
					sprintf( __( 'Plugin matching the UpdraftCentral backdoors: %s', 'sentinel-shield' ), (string) ( $data['Name'] ?? $file ) ),
					/* translators: %s: plugin file. */
					sprintf( __( 'File: wp-content/plugins/%s.', 'sentinel-shield' ), $file ) . ' '
						. ( $markers
							/* translators: %s: what was found. */
							? sprintf( __( 'Found: %s.', 'sentinel-shield' ), implode( '; ', array_column( $markers, 2 ) ) )
							: __( 'Its name is one of the 99 used by the plugins installed through stolen UpdraftCentral keys on 18 and 19 October 2026. Approve it if you installed it yourself.', 'sentinel-shield' ) )
						. ' ' . __( 'These plugins create an account with a known password when a secret parameter is requested. Delete the plugin and any account it created, and change administrator passwords.', 'sentinel-shield' ),
					'updraft-plugin:' . $file,
					self::fingerprint( WP_PLUGIN_DIR . '/' . $file )
				);
			}

			if ( 'updraftplus.php' !== basename( $file ) ) {
				continue;
			}
			$version  = (string) ( $data['Version'] ?? '' );
			$keys     = get_site_option( 'updraft_central_localkeys' );
			$keys     = is_array( $keys ) ? $keys : array();
			$old_keys = count( array_filter( $keys, static fn( $k ): bool => is_array( $k ) && (int) ( $k['created'] ?? 0 ) < Advisories::UPDRAFT_CUTOFF ) );
			if ( Advisories::updraft_forgeable( $version ) ) {
				$severity = 'critical';
				/* translators: %s: version. */
				$detail = sprintf( __( 'UpdraftPlus %s accepts forged UpdraftCentral commands without any key (CVE-2026-10795), which attackers still try. Update to 1.26.13 (Premium 2.26.13) or later now.', 'sentinel-shield' ), $version );
			} elseif ( Advisories::updraft_outdated( $version ) && $keys ) {
				$severity = 'critical';
				/* translators: 1: version, 2: number of keys. */
				$detail = sprintf( __( 'UpdraftPlus %1$s still accepts the %2$d UpdraftCentral connection key(s) on this site. Keys stolen from TeamUpdraft were used on 18 and 19 October 2026 to install backdoor plugins. Update to 1.26.13 (Premium 2.26.13), which disconnects keys from before the incident, then reconnect.', 'sentinel-shield' ), $version, count( $keys ) );
			} elseif ( $old_keys > 0 ) {
				$severity = 'warning';
				/* translators: %d: number of keys. */
				$detail = sprintf( __( '%d UpdraftCentral connection key(s) on this site were created before the TeamUpdraft incident (22:00 BST, 18 October 2026). Delete them under Settings → UpdraftPlus → Advanced Tools → UpdraftCentral and reconnect.', 'sentinel-shield' ), $old_keys );
			} elseif ( Advisories::updraft_outdated( $version ) ) {
				$severity = 'notice';
				/* translators: %s: version. */
				$detail = sprintf( __( 'UpdraftPlus %s is older than 1.26.13 (Premium 2.26.13). This site has no UpdraftCentral keys, so the incident does not reach it, but update anyway.', 'sentinel-shield' ), $version );
			} else {
				continue;
			}
			$this->add(
				'advisories',
				$severity,
				/* translators: %s: version. */
				sprintf( __( 'UpdraftPlus %s and the UpdraftCentral key theft', 'sentinel-shield' ), $version ),
				$detail . ' ' . __( 'If you do not use UpdraftCentral, "Refuse UpdraftCentral remote commands" on the Malware Lockdown tab blocks the channel entirely.', 'sentinel-shield' ),
				'updraft:' . $file,
				md5( $version . '|' . count( $keys ) . '|' . $old_keys )
			);
		}
	}

	/**
	 * Accounts created by the incidents' backdoors.
	 */
	private function advisory_accounts(): void {
		global $wpdb;
		$logins = Advisories::UPDRAFT_LOGINS;
		$rows   = (array) $wpdb->get_results( $wpdb->prepare( 'SELECT ID, user_login, user_email, user_registered FROM %i WHERE user_login IN (' . implode( ',', array_fill( 0, count( $logins ), '%s' ) ) . ') OR user_login LIKE %s OR user_email LIKE %s ORDER BY ID LIMIT 50', $wpdb->users, ...array_merge( $logins, array( $wpdb->esc_like( 'wpsupport_' ) . '%', '%' . $wpdb->esc_like( '@wp-mail.net' ) ) ) ), ARRAY_A ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber -- Read-only scan; the placeholders are generated.
		foreach ( $rows as $row ) {
			$updraft = in_array( strtolower( (string) $row['user_login'] ), $logins, true );
			$this->add(
				'advisories',
				'critical',
				/* translators: 1: login, 2: user ID, 3: email. */
				sprintf( __( 'Account created by a known backdoor: %1$s (ID %2$d, %3$s)', 'sentinel-shield' ), $row['user_login'], $row['ID'], $row['user_email'] ),
				( $updraft
					? __( 'This login was created by the plugins installed through stolen UpdraftCentral keys; its password is known to the attackers.', 'sentinel-shield' )
					: __( 'Administrators named wpsupport_… or with a @wp-mail.net address are created by the Rank Math PRO backdoor (CVE-2026-111862).', 'sentinel-shield' ) )
					. ' ' . __( 'Delete the account (attribute its content to someone else) and change every administrator password.', 'sentinel-shield' ),
				'backdoor-user:' . $row['ID'],
				md5( $row['ID'] . '|' . $row['user_login'] . '|' . $row['user_email'] )
			);
		}
		foreach ( $this->admins->privileged_users() as $user ) {
			if ( str_ends_with( strtolower( (string) $user['email'] ), '@example.com' ) ) {
				$this->add(
					'advisories',
					'warning',
					/* translators: 1: login, 2: user ID. */
					sprintf( __( 'Administrator with an @example.com address: %1$s (ID %2$d)', 'sentinel-shield' ), $user['login'], $user['id'] ),
					__( 'example.com cannot receive mail, so no real person uses it. The accounts created through stolen UpdraftCentral keys used it, with names such as "System Team" or "Web Tech". Approve this if it is a test account you made.', 'sentinel-shield' ),
					'example-admin:' . $user['id'],
					md5( $user['id'] . '|' . $user['login'] . '|' . $user['email'] )
				);
			}
		}
	}

	/**
	 * SSH keys of the account PHP runs as, which the Rank Math PRO backdoor adds to.
	 */
	private function advisory_ssh(): void {
		if ( ! function_exists( 'posix_getpwuid' ) || ! function_exists( 'posix_geteuid' ) ) {
			return;
		}
		$info = posix_getpwuid( posix_geteuid() );
		$home = is_array( $info ) ? $info['dir'] : '';
		$file = $home . '/.ssh/authorized_keys';
		if ( '' === $home || ! @is_file( $file ) || ! @is_readable( $file ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- open_basedir may forbid the home folder.
			return;
		}
		$text    = $this->read( $file );
		$keys    = (int) preg_match_all( '/^\s*(?:[a-z0-9-]+=\S*\s+)*(?:ssh-|ecdsa-|sk-)/mi', $text );
		$changed = (int) @filemtime( $file ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- See above.
		if ( 0 === $keys ) {
			return;
		}
		$this->add(
			'advisories',
			$changed >= Advisories::RANKMATH_WINDOW[0] ? 'warning' : 'notice',
			/* translators: 1: number of keys, 2: account name. */
			sprintf( _n( '%1$d SSH key can log in as %2$s, the account PHP runs as', '%1$d SSH keys can log in as %2$s, the account PHP runs as', $keys, 'sentinel-shield' ), $keys, is_array( $info ) ? $info['name'] : '?' ),
			/* translators: 1: file, 2: date. */
			sprintf( __( '%1$s was last changed on %2$s. The Rank Math PRO backdoor adds its own key here. Approve this if you recognize every key; you will be told if the file changes. A plugin cannot read crontabs: also run "crontab -l" as this account and look for lines tagged #ms6v46.', 'sentinel-shield' ), $file, gmdate( 'Y-m-d H:i', $changed ) . ' UTC' ),
			'ssh-keys',
			md5( $text )
		);
	}

	/**
	 * Whether this PHP build has the PHP2Shell fixes.
	 */
	private function advisory_php(): void {
		$status = Advisories::php_status_now();
		if ( 'fixed' === $status['state'] ) {
			return;
		}
		$gaps = Advisories::php_stopgaps( 'ini_get' );
		$this->add(
			'advisories',
			'vulnerable' === $status['state'] ? 'critical' : 'warning',
			'vulnerable' === $status['state']
				/* translators: 1: PHP version, 2: fixed version. */
				? sprintf( __( 'PHP %1$s has the PHP2Shell flaws (fixed in %2$s)', 'sentinel-shield' ), PHP_VERSION, $status['fixed'] )
				/* translators: %s: PHP version. */
				: sprintf( __( 'PHP %s: PHP2Shell fix not confirmed', 'sentinel-shield' ), PHP_VERSION ),
			( 'vulnerable' === $status['state']
				? __( 'CVE-2026-109618 and CVE-2026-109619 let an unauthenticated request run code on the server before WordPress loads, and are being exploited. Ask your host to update PHP now.', 'sentinel-shield' )
				: __( 'This PHP comes from a distribution package or a branch with no upstream fix, so its version number does not show whether the PHP2Shell fixes (CVE-2026-109618, CVE-2026-109619) were backported. Check the package changelog for those CVE numbers, then approve this finding.', 'sentinel-shield' ) )
				/* translators: 1: server API, 2: list of settings. */
				. ' ' . sprintf( __( 'Server API: %1$s. Until PHP is updated, set in php.ini or the PHP-FPM pool (not .user.ini) and restart PHP: %2$s, and limit request body size at the web server.', 'sentinel-shield' ), PHP_SAPI, $gaps ? implode( ', ', $gaps ) : __( 'the recommended settings are already in place', 'sentinel-shield' ) ),
			'php2shell',
			md5( PHP_VERSION . '|' . PHP_SAPI . '|' . implode( ',', $gaps ) )
		);
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
			self::fingerprint( $path )
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
			'uploads'  => $this->in_uploads,
		);
	}

	/**
	 * Updates the approved flag of a finding in the stored report.
	 *
	 * @param string $id       Finding ID.
	 * @param bool   $approved New state.
	 */
	private static function mark_in_report( string $id, bool $approved ): void {
		foreach ( array( self::REPORT_OPTION, FileIntegrity::REPORT_OPTION, FileIntegrity::STATE_OPTION, self::UPLOADS_STATE ) as $option ) {
			$report = get_site_option( $option );
			$key    = self::UPLOADS_STATE === $option ? 'carried' : 'findings';
			if ( ! is_array( $report ) || empty( $report[ $key ] ) ) {
				continue;
			}
			$changed = false;
			foreach ( $report[ $key ] as &$finding ) {
				if ( $finding['id'] === $id ) {
					$finding['approved'] = $approved;
					$finding['severity'] = $approved ? 'ok' : $finding['original'];
					$changed             = true;
				}
			}
			unset( $finding );
			if ( $changed ) {
				update_site_option( $option, $report );
			}
		}
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
		if ( ! is_file( $path ) ) {
			return '';
		}
		if ( ! is_readable( $path ) ) {
			$this->note( 'unreadable', $path );
			return '';
		}
		++$this->coverage['read'];
		if ( (int) filesize( $path ) > self::MAX_READ ) {
			$this->note( 'partial', $path );
		}
		return (string) file_get_contents( $path, false, null, 0, self::MAX_READ ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file inspection.
	}

	/**
	 * Remembers a file that was read only partly or not at all.
	 *
	 * @param string $kind partial|unreadable.
	 * @param string $path Path.
	 */
	private function note( string $kind, string $path ): void {
		$rel = CronInspector::relative( $path );
		if ( count( $this->coverage[ $kind ] ) < 50 && ! in_array( $rel, $this->coverage[ $kind ], true ) ) {
			$this->coverage[ $kind ][] = $rel;
		}
	}

	/**
	 * Whether a file of this plugin matches the release's checksums.sha256
	 * (true when there is no checksum file, as in a development copy).
	 *
	 * @param string $path File inside the plugin folder.
	 */
	public static function own_file_intact( string $path ): bool {
		$root = dirname( SENTINEL_SHIELD_FILE );
		$list = $root . '/checksums.sha256';
		if ( ! is_file( $list ) ) {
			return true;
		}
		$rel = ltrim( substr( wp_normalize_path( $path ), strlen( wp_normalize_path( $root ) ) ), '/' );
		foreach ( (array) file( $list, FILE_IGNORE_NEW_LINES ) as $line ) {
			$parts = preg_split( '/\s+\*?/', trim( (string) $line ), 2 );
			if ( is_array( $parts ) && 2 === count( $parts ) && ltrim( $parts[1], './' ) === $rel ) {
				return hash_equals( strtolower( $parts[0] ), (string) hash_file( 'sha256', $path ) );
			}
		}
		return false;
	}

	/**
	 * Content fingerprint used for approvals: SHA-1 of the whole file up to
	 * 8 MB; for larger files, of their size, modification time and first and
	 * last megabyte (appending or prepending code still changes it), so a huge
	 * log or archive does not cost a full read on every scan.
	 *
	 * @param string $path File.
	 */
	public static function fingerprint( string $path ): string {
		$size = @filesize( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Vanished file: empty fingerprint.
		if ( false === $size ) {
			return '';
		}
		if ( $size <= 8 * MB_IN_BYTES ) {
			return (string) @sha1_file( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Unreadable: empty fingerprint.
		}
		$h = @fopen( $path, 'rb' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- Local file inspection.
		if ( false === $h ) {
			return '';
		}
		$head = (string) fread( $h, MB_IN_BYTES ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fread -- Local file inspection.
		fseek( $h, -MB_IN_BYTES, SEEK_END );
		$tail = (string) fread( $h, MB_IN_BYTES ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fread -- Local file inspection.
		fclose( $h ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- Local file inspection.
		return 'big:' . sha1( $size . '|' . (int) @filemtime( $path ) . '|' . $head . '|' . $tail ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- See above.
	}

	/**
	 * Largest part of a file the scan reads (bytes).
	 */
	public static function max_read(): int {
		return self::MAX_READ;
	}
}
