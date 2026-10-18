<?php
/**
 * Verifies WordPress core and plugin files against WordPress.org checksums.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Lockdown;

use SentinelShield\Cron\CronInspector;
use SentinelShield\Support\FileWalk;
use SentinelShield\Support\Mutex;

defined( 'ABSPATH' ) || exit;

/**
 * WordPress.org publishes a hash of every file of every core release and of
 * every plugin version it hosts. A file that differs from its published hash,
 * or a PHP file in a core folder that no release contains, did not come from
 * WordPress.org: on a site that does not edit core or plugin code, that means
 * tampering. This is an authoritative check, unlike pattern matching, which
 * only finds known tricks.
 *
 * The check runs in slices (a time budget per run) and keeps its position
 * between runs, so large sites are checked completely instead of cut off.
 * Each completed pass stores a report with its coverage: what was verified,
 * what could not be (themes, premium plugins, versions without published
 * checksums) and why. Nothing is ever changed or deleted.
 */
final class FileIntegrity {

	public const STATE_OPTION  = 'sentinel_shield_integrity_state';
	public const REPORT_OPTION = 'sentinel_shield_integrity_report';
	public const CACHE_PREFIX  = 'sentinel_shield_sums_';

	public const CHECKS = array( 'core_files', 'plugin_files' );

	private const PLUGIN_URL     = 'https://downloads.wordpress.org/plugin-checksums/%s/%s.json';
	private const MAX_PER_TARGET = 50;
	private const LIST_MAX       = 20;
	private const PHP_LIKE       = '/\.(php[0-9]?|phtml|phar|pht|inc)$/i';

	/**
	 * Fetches a URL: fn( string $url ): array{code:int, body:string}|null.
	 *
	 * @var \Closure
	 */
	private \Closure $fetch;

	/**
	 * State of the pass in progress.
	 *
	 * @var array<string, mixed>
	 */
	private array $state = array();

	/**
	 * Slice deadline (microtime).
	 *
	 * @var float
	 */
	private float $deadline = 0.0;

	/**
	 * Files handled in this slice.
	 *
	 * @var int
	 */
	private int $work = 0;

	/**
	 * Checksums of the current target, memoized for the slice.
	 *
	 * @var array<string, mixed>|null
	 */
	private ?array $sums = null;

	/**
	 * Constructor.
	 *
	 * @param \Closure|null $fetch    fn( string $url ): ?array{code:int, body:string}; defaults to wp_remote_get().
	 * @param int           $min_work Files every slice handles even past its time budget, so a pass always moves on.
	 */
	public function __construct( ?\Closure $fetch = null, private int $min_work = 200 ) {
		$this->fetch = $fetch ?? static function ( string $url ): ?array {
			$response = wp_remote_get( $url, array( 'timeout' => 15 ) );
			if ( is_wp_error( $response ) ) {
				return null;
			}
			return array(
				'code' => (int) wp_remote_retrieve_response_code( $response ),
				'body' => (string) wp_remote_retrieve_body( $response ),
			);
		};
	}

	/**
	 * Labels and explanations of the two checks.
	 *
	 * @return array<string, array{0:string, 1:string}>
	 */
	public static function checks(): array {
		return array(
			'core_files'   => array( __( 'WordPress core files', 'sentinel-shield' ), __( 'Every core file is compared with the hash WordPress.org publishes for your version. Changed core files and PHP files in wp-admin or wp-includes that no release contains are how backdoors usually hide in core.', 'sentinel-shield' ) ),
			'plugin_files' => array( __( 'Plugin files', 'sentinel-shield' ), __( 'Plugins from WordPress.org are compared with the hashes published for the installed version. Changed files and PHP files that the plugin never shipped are reported.', 'sentinel-shield' ) ),
		);
	}

	/**
	 * Last completed pass.
	 *
	 * @return array<string, mixed>|null
	 */
	public static function report(): ?array {
		$report = get_site_option( self::REPORT_OPTION );
		return is_array( $report ) ? $report : null;
	}

	/**
	 * Pass in progress, if any.
	 *
	 * @return array<string, mixed>|null
	 */
	public static function state(): ?array {
		$state = get_site_option( self::STATE_OPTION );
		return is_array( $state ) ? $state : null;
	}

	/**
	 * Whether a pass is in progress.
	 */
	public static function in_progress(): bool {
		return null !== self::state();
	}

	/**
	 * Starts a new pass unless one is in progress (or $restart).
	 *
	 * @param bool $restart Discard a pass in progress.
	 */
	public function start( bool $restart = false ): void {
		if ( ! $restart && self::in_progress() ) {
			return;
		}
		update_site_option(
			self::STATE_OPTION,
			array(
				'started'  => time(),
				'runs'     => 0,
				'seconds'  => 0.0,
				'targets'  => self::targets(),
				'i'        => 0,
				'phase'    => 'listed',
				'pos'      => '',
				'findings' => array(),
				'coverage' => array(),
				'hashed'   => 0,
			)
		);
	}

	/**
	 * Runs one slice of the pass in progress.
	 *
	 * @param float $budget Seconds to spend (INF for no limit).
	 * @return array{done:bool, busy:bool, report:array<string, mixed>|null, progress:array{done:int, total:int}}
	 */
	public function step( float $budget ): array {
		$out = Mutex::run(
			'integrity_scan',
			0,
			fn(): array => $this->step_locked( $budget ),
			null
		);
		if ( null === $out ) {
			return array(
				'done'     => false,
				'busy'     => true,
				'report'   => null,
				'progress' => self::progress( self::state() ),
			);
		}
		return $out;
	}

	/**
	 * Runs a whole pass now (WP-CLI).
	 *
	 * @return array<string, mixed> The report.
	 */
	public function run_all(): array {
		$this->start( true );
		do {
			$result = $this->step( INF );
		} while ( ! $result['done'] && ! $result['busy'] );
		return (array) ( $result['report'] ?? self::report() );
	}

	/**
	 * Progress of a pass: targets finished and total.
	 *
	 * @param array<string, mixed>|null $state State.
	 * @return array{done:int, total:int}
	 */
	public static function progress( ?array $state ): array {
		return array(
			'done'  => (int) ( $state['i'] ?? 0 ),
			'total' => count( (array) ( $state['targets'] ?? array() ) ),
		);
	}

	/**
	 * Slice body, run under the lock.
	 *
	 * @param float $budget Seconds.
	 * @return array{done:bool, busy:bool, report:array<string, mixed>|null, progress:array{done:int, total:int}}
	 */
	private function step_locked( float $budget ): array {
		$state = self::state();
		if ( null === $state ) {
			return array(
				'done'     => true,
				'busy'     => false,
				'report'   => self::report(),
				'progress' => array(
					'done'  => 0,
					'total' => 0,
				),
			);
		}
		$this->state    = $state;
		$start          = microtime( true );
		$this->deadline = is_finite( $budget ) ? $start + $budget : INF;
		$this->work     = 0;
		++$this->state['runs'];

		$targets = (array) $this->state['targets'];
		$total   = count( $targets );
		while ( $this->state['i'] < $total && ! $this->out_of_time() ) {
			Mutex::renew( 'integrity_scan' );
			$target = (array) $targets[ $this->state['i'] ];
			if ( $this->target( $target ) ) {
				++$this->state['i'];
				$this->state['phase'] = 'listed';
				$this->state['pos']   = '';
				$this->sums           = null;
			}
		}
		$this->state['seconds'] = round( (float) $this->state['seconds'] + microtime( true ) - $start, 2 );

		if ( $this->state['i'] < $total ) {
			update_site_option( self::STATE_OPTION, $this->state );
			return array(
				'done'     => false,
				'busy'     => false,
				'report'   => null,
				'progress' => self::progress( $this->state ),
			);
		}
		$report = $this->finish();
		return array(
			'done'     => true,
			'busy'     => false,
			'report'   => $report,
			'progress' => self::progress( $this->state ),
		);
	}

	/**
	 * Stores the completed pass as the report and clears the state.
	 *
	 * @return array<string, mixed>
	 */
	private function finish(): array {
		$before = array();
		foreach ( (array) ( self::report()['findings'] ?? array() ) as $finding ) {
			if ( IntegrityScanner::is_alert( $finding ) ) {
				$before[ $finding['id'] ] = true;
			}
		}
		$findings = (array) $this->state['findings'];
		$new      = array();
		foreach ( $findings as $finding ) {
			if ( IntegrityScanner::is_alert( $finding ) && ! isset( $before[ $finding['id'] ] ) ) {
				$new[] = (string) $finding['id'];
			}
		}
		$report = array(
			'time'     => time(),
			'started'  => (int) $this->state['started'],
			'duration' => (float) $this->state['seconds'],
			'runs'     => (int) $this->state['runs'],
			'hashed'   => (int) $this->state['hashed'],
			'coverage' => (array) $this->state['coverage'],
			'findings' => $findings,
			'new'      => $new,
		);
		update_site_option( self::REPORT_OPTION, $report );
		delete_site_option( self::STATE_OPTION );
		return $report;
	}

	/**
	 * What one pass covers: core, then each plugin folder; single-file plugins,
	 * must-use plugins and themes are listed as not verifiable.
	 *
	 * @return list<array<string, string>>
	 */
	public static function targets(): array {
		require_once ABSPATH . 'wp-admin/includes/plugin.php';
		$targets = array(
			array(
				'type'    => 'core',
				'slug'    => 'wordpress',
				'name'    => 'WordPress',
				'version' => (string) get_bloginfo( 'version' ),
				'dir'     => untrailingslashit( ABSPATH ),
			),
		);
		$seen    = array();
		foreach ( get_plugins() as $file => $data ) {
			$slug = str_contains( $file, '/' ) ? dirname( $file ) : '';
			if ( '' !== $slug && isset( $seen[ $slug ] ) ) {
				continue;
			}
			$targets[] = array(
				'type'    => '' === $slug ? 'single' : 'plugin',
				'slug'    => '' === $slug ? $file : $slug,
				'name'    => (string) ( $data['Name'] ?? $file ),
				'version' => (string) ( $data['Version'] ?? '' ),
				'dir'     => '' === $slug ? WP_PLUGIN_DIR . '/' . $file : WP_PLUGIN_DIR . '/' . $slug,
			);
			if ( '' !== $slug ) {
				$seen[ $slug ] = true;
			}
		}
		foreach ( wp_get_themes() as $slug => $theme ) {
			$targets[] = array(
				'type'    => 'theme',
				'slug'    => (string) $slug,
				'name'    => (string) $theme->get( 'Name' ),
				'version' => (string) $theme->get( 'Version' ),
				'dir'     => $theme->get_stylesheet_directory(),
			);
		}
		return $targets;
	}

	/**
	 * Works on one target. Returns true when it is finished.
	 *
	 * @param array<string, string> $target Target.
	 */
	private function target( array $target ): bool {
		$key = $target['type'] . ':' . $target['slug'];
		if ( ! isset( $this->state['coverage'][ $key ] ) ) {
			$this->state['coverage'][ $key ] = array(
				'type'            => $target['type'],
				'name'            => $target['name'],
				'version'         => $target['version'],
				'status'          => 'checking',
				'reason'          => '',
				'files'           => 0,
				'modified'        => 0,
				'missing'         => array(),
				'missing_total'   => 0,
				'truncated'       => array(),
				'truncated_total' => 0,
				'extra'           => 0,
				'listed'          => 0,
				'omitted'         => 0,
			);
		}
		$cov = &$this->state['coverage'][ $key ];
		if ( 'single' === $target['type'] || 'theme' === $target['type'] ) {
			$cov['status'] = 'unverifiable';
			$cov['reason'] = 'theme' === $target['type'] ? 'theme' : 'single_file';
			return true;
		}
		$sums = $this->sums ?? $this->checksums( $target );
		if ( isset( $sums['error'] ) ) {
			$cov['status'] = 'unverifiable';
			$cov['reason'] = (string) $sums['error'];
			return true;
		}
		$this->sums = $sums;
		$files      = (array) $sums['files'];

		if ( 'listed' === $this->state['phase'] ) {
			$paths = array_keys( $files );
			sort( $paths, SORT_STRING );
			$start = (int) ( '' === $this->state['pos'] ? 0 : $this->state['pos'] );
			$count = count( $paths );
			for ( $n = $start; $n < $count; $n++ ) {
				if ( $this->out_of_time() ) {
					$this->state['pos'] = $n;
					return false;
				}
				$this->listed( $target, $paths[ $n ], (array) $files[ $paths[ $n ] ], $cov );
			}
			$this->state['phase'] = 'extra';
			$this->state['pos']   = '';
		}

		if ( ! $this->extra( $target, $files, $cov ) ) {
			return false;
		}
		if ( $cov['truncated_total'] ) {
			$this->cut_off_finding( $target, $cov );
		}
		if ( $cov['missing_total'] ) {
			$this->missing_finding( $target, $cov );
		}
		$cov['status'] = ( $cov['modified'] || $cov['extra'] || $cov['truncated_total'] ) ? 'problems' : 'verified';
		return true;
	}

	/**
	 * Compares one published file with the file on disk.
	 *
	 * @param array<string, string> $target Target.
	 * @param string                $rel    Path relative to the target folder.
	 * @param array<string, mixed>  $sum    {algo, hashes}.
	 * @param array<string, mixed>  $cov    Coverage entry.
	 */
	private function listed( array $target, string $rel, array $sum, array &$cov ): void {
		++$this->work;
		$path = $target['dir'] . '/' . $rel;
		if ( ! is_file( $path ) ) {
			if ( count( $cov['missing'] ) < self::LIST_MAX ) {
				$cov['missing'][] = $rel;
			}
			++$cov['missing_total'];
			return;
		}
		++$cov['files'];
		++$this->state['hashed'];
		$hash = (string) @hash_file( (string) $sum['algo'], $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Unreadable files are reported as changed.
		if ( in_array( $hash, (array) $sum['hashes'], true ) ) {
			return;
		}
		++$cov['modified'];
		if ( 'core' === $target['type'] ) {
			$this->finding( $target, 'core_files', $path, 'critical', __( 'This core file differs from the official WordPress copy. Core files are never edited by WordPress itself; reinstall WordPress (Dashboard → Updates → Re-install) unless you know who changed it.', 'sentinel-shield' ), $cov );
		} else {
			/* translators: 1: plugin name, 2: version. */
			$this->finding( $target, 'plugin_files', $path, 'warning', sprintf( __( 'This file differs from %1$s %2$s as published on WordPress.org. Reinstall the plugin unless you edited it yourself.', 'sentinel-shield' ), $target['name'], $target['version'] ), $cov );
		}
	}

	/**
	 * Looks for files the release does not contain. Returns true when done.
	 *
	 * Core: PHP and other files in wp-admin and wp-includes, and PHP files in the
	 * WordPress folder itself (except wp-config.php). Plugins: PHP files only,
	 * since plugins create caches and logs in their own folder.
	 *
	 * @param array<string, string> $target Target.
	 * @param array<string, mixed>  $files  Published files.
	 * @param array<string, mixed>  $cov    Coverage entry.
	 */
	private function extra( array $target, array $files, array &$cov ): bool {
		$core = 'core' === $target['type'];
		if ( $core && '' === $this->state['pos'] ) {
			foreach ( (array) @scandir( $target['dir'] ) as $name ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Unreadable folder: nothing to list.
				$name = (string) $name;
				if ( preg_match( self::PHP_LIKE, $name ) && ! isset( $files[ $name ] ) && 'wp-config.php' !== $name && ! str_starts_with( $name, '.' ) && is_file( $target['dir'] . '/' . $name ) ) {
					++$cov['extra'];
					$this->finding( $target, 'core_files', $target['dir'] . '/' . $name, 'warning', __( 'A PHP file in the WordPress folder that is not part of WordPress. Some hosts and tools add files here; backdoors are also often dropped here.', 'sentinel-shield' ), $cov );
				}
			}
			$this->state['pos'] = 'wp-admin/';
		}
		$roots = $core ? array( 'wp-admin', WPINC ) : array( '' );
		foreach ( $roots as $root ) {
			$pos = (string) $this->state['pos'];
			if ( $core && ! str_starts_with( $pos, $root . '/' ) ) {
				if ( strcmp( $pos, $root . '/' ) > 0 ) {
					continue; // This folder was finished in an earlier slice.
				}
				$pos = $root . '/';
			}
			$prefix = $core ? $root . '/' : '';
			$walk   = new FileWalk( $target['dir'] . ( $core ? '/' . $root : '' ) );
			$done   = $walk->run(
				substr( $pos, strlen( $prefix ) ),
				function ( string $path, string $rel ) use ( $target, $files, $prefix, $core, &$cov ): void {
					++$this->work;
					if ( isset( $files[ $prefix . $rel ] ) ) {
						return;
					}
					if ( $this->cut_off_copy( $target, $prefix . $rel, $path, $files, $cov ) ) {
						return;
					}
					$php = 1 === preg_match( self::PHP_LIKE, $rel );
					if ( ! $core && ! $php ) {
						return;
					}
					++$cov['extra'];
					if ( $core ) {
						$this->finding( $target, 'core_files', $path, $php ? 'critical' : 'warning', __( 'This file is not part of any WordPress release but sits in a core folder. Backdoors are often hidden this way; reinstalling WordPress does not remove extra files.', 'sentinel-shield' ), $cov );
					} else {
						/* translators: 1: plugin name, 2: version. */
						$this->finding( $target, 'plugin_files', $path, 'warning', sprintf( __( 'A PHP file that %1$s %2$s does not contain. A few plugins generate PHP files; otherwise it was added by someone else.', 'sentinel-shield' ), $target['name'], $target['version'] ), $cov );
					}
				},
				fn(): bool => $this->out_of_time()
			);
			if ( ! $done ) {
				$this->state['pos'] = $prefix . $walk->cursor;
				return false;
			}
			// Next: wp-includes after wp-admin; "~" sorts after every path and means done.
			$this->state['pos'] = ( $core && 'wp-admin' === $root ) ? WPINC . '/' : '~';
		}
		return true;
	}

	/**
	 * Whether an unexpected file is an intact copy of a missing published file
	 * saved under a shortened name. Some unpacking tools (including WP-CLI's
	 * `wp core download` on some systems) cut paths longer than 100 characters,
	 * so WordPress cannot find the file. That is a broken install, not tampering:
	 * the content must match the published hash exactly.
	 *
	 * @param array<string, string> $target Target.
	 * @param string                $rel    Path relative to the target folder.
	 * @param string                $path   Absolute path.
	 * @param array<string, mixed>  $files  Published files.
	 * @param array<string, mixed>  $cov    Coverage entry.
	 */
	private function cut_off_copy( array $target, string $rel, string $path, array $files, array &$cov ): bool {
		foreach ( $files as $full => $sum ) {
			$full = (string) $full;
			if ( strlen( $full ) <= strlen( $rel ) || ! str_starts_with( $full, $rel ) || is_file( $target['dir'] . '/' . $full ) ) {
				continue;
			}
			if ( ! in_array( (string) @hash_file( (string) $sum['algo'], $path ), (array) $sum['hashes'], true ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Unreadable: not a match.
				continue;
			}
			if ( count( $cov['truncated'] ) < self::LIST_MAX ) {
				$cov['truncated'][] = $full;
			}
			++$cov['truncated_total'];
			// It was counted as missing; the cut-off finding explains it instead.
			$at = array_search( $full, $cov['missing'], true );
			if ( false !== $at ) {
				array_splice( $cov['missing'], (int) $at, 1 );
			}
			$cov['missing_total'] = max( 0, (int) $cov['missing_total'] - 1 );
			return true;
		}
		return false;
	}

	/**
	 * One finding per target for files saved under cut-off names.
	 *
	 * @param array<string, string> $target Target.
	 * @param array<string, mixed>  $cov    Coverage entry.
	 */
	private function cut_off_finding( array $target, array $cov ): void {
		$total = (int) $cov['truncated_total'];
		$list  = implode( ', ', (array) $cov['truncated'] ) . ( $total > count( (array) $cov['truncated'] ) ? ', …' : '' );
		$this->add(
			'core' === $target['type'] ? 'core_files' : 'plugin_files',
			'warning',
			/* translators: 1: name, 2: number of files. */
			sprintf( _n( '%1$s: %2$d file was saved under a cut-off name', '%1$s: %2$d files were saved under cut-off names', $total, 'sentinel-shield' ), $target['name'], $total ),
			/* translators: %s: list of files. */
			sprintf( __( 'These files are intact copies of official files, but their names were shortened when the package was unpacked (paths over 100 characters), so WordPress cannot load them and features that need them fail. This is a damaged installation, not tampering. Some unpacking tools do this, including wp core download on some systems. Reinstall from the official zip (for core: Dashboard → Updates → Re-install), then delete the shortened copies. Affected: %s.', 'sentinel-shield' ), $list ),
			'cut_off:' . $target['type'] . ':' . $target['slug'],
			md5( $total . '|' . implode( '|', (array) $cov['truncated'] ) ),
			$target
		);
	}

	/**
	 * Adds a file finding, graded up by malware traits.
	 *
	 * @param array<string, string> $target   Target.
	 * @param string                $check    core_files|plugin_files.
	 * @param string                $path     Absolute path.
	 * @param string                $severity Base severity.
	 * @param string                $detail   Explanation.
	 * @param array<string, mixed>  $cov      Coverage entry.
	 */
	private function finding( array $target, string $check, string $path, string $severity, string $detail, array &$cov ): void {
		if ( $cov['listed'] >= self::MAX_PER_TARGET ) {
			++$cov['omitted'];
			return;
		}
		++$cov['listed'];
		// Every reported file is read, whatever its name: code can be included from any file.
		$reasons = IntegrityScanner::signatures( (string) @file_get_contents( $path, false, null, 0, 2097152 ) ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file inspection.
		$rel     = CronInspector::relative( $path );
		$this->add(
			$check,
			IntegrityScanner::worst( $reasons, $severity ),
			$reasons
				/* translators: %s: file path. */
				? sprintf( __( 'Suspicious code in %s', 'sentinel-shield' ), $rel )
				: $rel,
			trim( $detail . ( $reasons ? ' ' . sprintf( /* translators: %s: list. */ __( 'Found: %s.', 'sentinel-shield' ), implode( '; ', array_unique( array_column( $reasons, 0 ) ) ) ) : '' ) ),
			'file:' . $path,
			IntegrityScanner::fingerprint( $path ),
			$target
		);
	}

	/**
	 * One finding per target for files missing from disk.
	 *
	 * @param array<string, string> $target Target.
	 * @param array<string, mixed>  $cov    Coverage entry.
	 */
	private function missing_finding( array $target, array $cov ): void {
		$missing = (array) $cov['missing'];
		$total   = (int) $cov['missing_total'];
		$list    = implode( ', ', $missing ) . ( $total > count( $missing ) ? ', …' : '' );
		$this->add(
			'core' === $target['type'] ? 'core_files' : 'plugin_files',
			'notice',
			/* translators: 1: name, 2: number of files. */
			sprintf( _n( '%1$s: %2$d published file is missing', '%1$s: %2$d published files are missing', $total, 'sentinel-shield' ), $target['name'], $total ),
			/* translators: %s: list of files. */
			sprintf( __( 'Missing: %s. Some hardening guides delete files such as readme.html; otherwise an update may have failed.', 'sentinel-shield' ), $list ),
			'missing:' . $target['type'] . ':' . $target['slug'],
			md5( $total . '|' . implode( '|', $missing ) ),
			$target
		);
	}

	/**
	 * Records a finding in the scanner's shape; approved ones become "ok".
	 *
	 * @param string                $check    Check slug.
	 * @param string                $severity Severity.
	 * @param string                $title    Title.
	 * @param string                $detail   Explanation.
	 * @param string                $key      Identity.
	 * @param string                $hash     Fingerprint ('' = not approvable).
	 * @param array<string, string> $target   Target.
	 */
	private function add( string $check, string $severity, string $title, string $detail, string $key, string $hash, array $target ): void {
		$id                        = md5( $check . '|' . $key );
		$approved                  = '' !== $hash && ( IntegrityScanner::baseline()[ $id ]['hash'] ?? null ) === $hash;
		$this->state['findings'][] = array(
			'id'       => $id,
			'check'    => $check,
			'target'   => $target['type'] . ':' . $target['slug'],
			'severity' => $approved ? 'ok' : $severity,
			'original' => $severity,
			'approved' => $approved,
			'title'    => $title,
			'detail'   => $detail,
			'hash'     => $hash,
		);
	}

	/**
	 * Published checksums for a target, cached: {files: path => {algo, hashes}} or {error}.
	 *
	 * @param array<string, string> $target Target.
	 * @return array<string, mixed>
	 */
	private function checksums( array $target ): array {
		$cache_key = self::CACHE_PREFIX . md5( $target['type'] . '|' . $target['slug'] . '|' . $target['version'] . '|' . get_locale() );
		$cached    = get_site_transient( $cache_key );
		if ( is_array( $cached ) ) {
			return $cached;
		}
		$this->work += 50; // A download counts like many files toward the slice's minimum.
		$result      = 'core' === $target['type'] ? $this->core_checksums( $target['version'] ) : $this->plugin_checksums( $target['slug'], $target['version'] );
		if ( 'fetch_failed' !== ( $result['error'] ?? '' ) ) {
			// Published checksums never change; "not published" is re-checked daily.
			set_site_transient( $cache_key, $result, isset( $result['error'] ) ? DAY_IN_SECONDS : 30 * DAY_IN_SECONDS );
		}
		return $result;
	}

	/**
	 * Core checksums (MD5) for a version, in the site's locale or en_US.
	 *
	 * @param string $version WordPress version.
	 * @return array<string, mixed>
	 */
	private function core_checksums( string $version ): array {
		foreach ( array_unique( array( get_locale(), 'en_US' ) ) as $locale ) {
			$url      = 'https://api.wordpress.org/core/checksums/1.0/?' . http_build_query(
				array(
					'version' => $version,
					'locale'  => $locale,
				)
			);
			$response = ( $this->fetch )( $url );
			if ( null === $response ) {
				return array( 'error' => 'fetch_failed' );
			}
			$data = json_decode( $response['body'], true );
			$sums = is_array( $data ) ? ( $data['checksums'][ $version ] ?? $data['checksums'] ?? null ) : null;
			if ( 200 === $response['code'] && is_array( $sums ) && $sums ) {
				$files = array();
				foreach ( $sums as $path => $md5 ) {
					if ( is_string( $md5 ) && ! str_starts_with( (string) $path, 'wp-content/' ) ) {
						$files[ (string) $path ] = array(
							'algo'   => 'md5',
							'hashes' => array( strtolower( $md5 ) ),
						);
					}
				}
				return array( 'files' => $files );
			}
		}
		return array( 'error' => 'no_checksums' );
	}

	/**
	 * Plugin checksums (SHA-256 where published, else MD5).
	 *
	 * @param string $slug    Plugin folder.
	 * @param string $version Version.
	 * @return array<string, mixed>
	 */
	private function plugin_checksums( string $slug, string $version ): array {
		if ( '' === $version || ! preg_match( '/^[a-z0-9._-]+$/i', $slug ) ) {
			return array( 'error' => 'no_checksums' );
		}
		$response = ( $this->fetch )( sprintf( self::PLUGIN_URL, rawurlencode( $slug ), rawurlencode( $version ) ) );
		if ( null === $response || $response['code'] >= 500 ) {
			return array( 'error' => 'fetch_failed' );
		}
		$data = json_decode( $response['body'], true );
		if ( 200 !== $response['code'] || ! is_array( $data ) || empty( $data['files'] ) || ! is_array( $data['files'] ) ) {
			return array( 'error' => 'not_published' );
		}
		$files = array();
		foreach ( $data['files'] as $path => $sum ) {
			$algo = isset( $sum['sha256'] ) ? 'sha256' : ( isset( $sum['md5'] ) ? 'md5' : '' );
			if ( '' === $algo ) {
				continue;
			}
			$files[ (string) $path ] = array(
				'algo'   => $algo,
				'hashes' => array_map( 'strtolower', array_map( 'strval', (array) $sum[ $algo ] ) ),
			);
		}
		return $files ? array( 'files' => $files ) : array( 'error' => 'not_published' );
	}

	/**
	 * Why a target could not be verified, in words.
	 *
	 * @param string $reason Reason code.
	 */
	public static function reason_text( string $reason ): string {
		$texts = array(
			'theme'         => __( 'WordPress.org publishes no checksums for themes. Themes are covered by the malware scan.', 'sentinel-shield' ),
			'single_file'   => __( 'Single-file plugin: WordPress.org checksums are published per plugin folder.', 'sentinel-shield' ),
			'not_published' => __( 'No checksums published: the plugin is not hosted on WordPress.org (premium or custom), or this version is not.', 'sentinel-shield' ),
			'no_checksums'  => __( 'WordPress.org has no checksums for this version.', 'sentinel-shield' ),
			'fetch_failed'  => __( 'WordPress.org could not be reached; it is tried again in the next pass.', 'sentinel-shield' ),
		);
		return $texts[ $reason ] ?? $reason;
	}

	/**
	 * Whether the slice has used up its time.
	 */
	private function out_of_time(): bool {
		return $this->work >= $this->min_work && microtime( true ) >= $this->deadline;
	}

	/**
	 * Cached checksums are kept in site transients; removes them all.
	 */
	public static function clear_cache(): void {
		global $wpdb;
		$like = $wpdb->esc_like( '_site_transient_' . self::CACHE_PREFIX ) . '%';
		if ( is_multisite() ) {
			$wpdb->query( $wpdb->prepare( 'DELETE FROM %i WHERE meta_key LIKE %s OR meta_key LIKE %s', $wpdb->sitemeta, $like, $wpdb->esc_like( '_site_transient_timeout_' . self::CACHE_PREFIX ) . '%' ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Bulk cleanup of our own transients.
		} else {
			$wpdb->query( $wpdb->prepare( 'DELETE FROM %i WHERE option_name LIKE %s OR option_name LIKE %s', $wpdb->options, $like, $wpdb->esc_like( '_site_transient_timeout_' . self::CACHE_PREFIX ) . '%' ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Bulk cleanup of our own transients.
		}
	}
}
