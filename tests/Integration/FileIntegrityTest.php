<?php
/**
 * WordPress.org checksum verification, the resumable file walk and the
 * malware scan's coverage and resumable uploads walk.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Tests\Integration;

use SentinelShield\Lockdown\AdminRegistry;
use SentinelShield\Lockdown\FileIntegrity;
use SentinelShield\Lockdown\IntegrityScanner;
use SentinelShield\Plugin;
use SentinelShield\Repository\EventRepository;
use SentinelShield\Settings;
use SentinelShield\Support\FileWalk;

final class FileIntegrityTest extends \WP_UnitTestCase {

	/**
	 * Files and folders created by a test, removed in tear_down (deepest first).
	 *
	 * @var list<string>
	 */
	private array $created = array();

	/**
	 * URLs the fake WordPress.org was asked for.
	 *
	 * @var list<string>
	 */
	private array $asked = array();

	public function set_up(): void {
		parent::set_up();
		foreach ( array( FileIntegrity::STATE_OPTION, FileIntegrity::REPORT_OPTION, IntegrityScanner::REPORT_OPTION, IntegrityScanner::BASELINE_OPTION, IntegrityScanner::UPLOADS_STATE ) as $option ) {
			delete_site_option( $option );
		}
		FileIntegrity::clear_cache();
		wp_clean_plugins_cache( false );
	}

	public function tear_down(): void {
		foreach ( array_reverse( $this->created ) as $path ) {
			if ( is_dir( $path ) ) {
				@rmdir( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			} elseif ( file_exists( $path ) ) {
				wp_delete_file( $path );
			}
		}
		FileIntegrity::clear_cache();
		wp_clean_plugins_cache( false );
		delete_site_option( Settings::OPTION );
		Plugin::instance()->container()->get( Settings::class )->refresh();
		parent::tear_down();
	}

	/**
	 * Writes a file, creating (and remembering) missing folders.
	 *
	 * @param string $path    Path.
	 * @param string $content Content.
	 */
	private function put( string $path, string $content ): string {
		$missing = array();
		for ( $dir = dirname( $path ); ! is_dir( $dir ); $dir = dirname( $dir ) ) {
			$missing[] = $dir;
		}
		foreach ( array_reverse( $missing ) as $dir ) {
			mkdir( $dir );
			$this->created[] = $dir;
		}
		file_put_contents( $path, $content );
		$this->created[] = $path;
		return $path;
	}

	/**
	 * MD5 of every core file as WordPress.org would publish it (computed from
	 * the files on disk, so an untouched install verifies).
	 *
	 * @return array<string, string>
	 */
	private static function core_md5(): array {
		$sums = array();
		foreach ( (array) scandir( ABSPATH ) as $name ) {
			if ( is_file( ABSPATH . $name ) && 'wp-config.php' !== $name ) {
				$sums[ (string) $name ] = md5_file( ABSPATH . $name );
			}
		}
		foreach ( array( 'wp-admin', 'wp-includes' ) as $root ) {
			( new FileWalk( ABSPATH . $root ) )->run(
				'',
				static function ( string $path, string $rel ) use ( &$sums, $root ): void {
					$sums[ $root . '/' . $rel ] = md5_file( $path );
				},
				static fn(): bool => false
			);
		}
		return $sums;
	}

	/**
	 * A FileIntegrity with a fake WordPress.org.
	 *
	 * @param array<string, string>      $core    Core path => md5.
	 * @param array<string, array|null> $plugins Slug => files (path => sha256), or null for "not hosted".
	 * @param int                        $min     Minimum work per slice.
	 * @param bool                       $offline Every request fails.
	 */
	private function verifier( array $core, array $plugins, int $min = 200, bool $offline = false ): FileIntegrity {
		return new FileIntegrity(
			function ( string $url ) use ( $core, $plugins, $offline ): ?array {
				$this->asked[] = $url;
				if ( $offline ) {
					return null;
				}
				if ( str_starts_with( $url, 'https://api.wordpress.org/core/checksums/1.0/' ) ) {
					parse_str( (string) wp_parse_url( $url, PHP_URL_QUERY ), $query );
					return array(
						'code' => 200,
						'body' => (string) wp_json_encode( array( 'checksums' => array( $query['version'] => $core ) ) ),
					);
				}
				if ( preg_match( '#plugin-checksums/([^/]+)/([^/]+)\.json$#', $url, $m ) && is_array( $plugins[ $m[1] ] ?? null ) ) {
					$files = array();
					foreach ( $plugins[ $m[1] ] as $path => $sha ) {
						$files[ $path ] = array(
							'md5'    => 'unused',
							'sha256' => $sha,
						);
					}
					return array(
						'code' => 200,
						'body' => (string) wp_json_encode( array( 'files' => $files ) ),
					);
				}
				return array(
					'code' => 404,
					'body' => '{"code":"not_found"}',
				);
			},
			$min
		);
	}

	/**
	 * A small plugin on disk plus its published checksums (with one file
	 * published differently, one file added locally and one deleted).
	 *
	 * @return array<string, string> Published path => sha256.
	 */
	private function fake_plugin(): array {
		$dir  = WP_PLUGIN_DIR . '/ss-fake';
		$main = $this->put( $dir . '/ss-fake.php', "<?php\n/**\n * Plugin Name: SS Fake\n * Version: 1.2.3\n */\n" );
		$inc  = $this->put( $dir . '/inc/helpers.php', "<?php\nfunction ss_fake_helper() { return 1; }\n" );
		$this->put( $dir . '/readme.txt', "=== SS Fake ===\n" );
		$this->put( $dir . '/cache/data.json', '{}' );
		$this->put( $dir . '/inc/evil.php', '<?php eval(base64_decode("ZWNobyAxOw=="));' );
		wp_clean_plugins_cache( false );
		return array(
			'ss-fake.php'      => hash_file( 'sha256', $main ),
			'inc/helpers.php'  => hash( 'sha256', 'the published version' ),
			'readme.txt'       => hash_file( 'sha256', $dir . '/readme.txt' ),
			'languages/x.mo'   => hash( 'sha256', 'deleted locally' ),
			'unused/inc.php'   => hash_file( 'sha256', $inc ),
		);
	}

	/**
	 * Findings of a report keyed by title.
	 *
	 * @param array<string, mixed> $report Report.
	 * @return array<string, array<string, mixed>>
	 */
	private static function by_title( array $report ): array {
		return array_column( (array) $report['findings'], null, 'title' );
	}

	public function test_file_walk_is_sorted_and_resumes_exactly(): void {
		$base = wp_get_upload_dir()['basedir'] . '/ss-walk';
		foreach ( array( 'b.txt', 'a/2.php', 'a/1.php', 'a/z/9.txt', 'a/m/5.txt', 'c/x.txt', 'A.txt' ) as $file ) {
			$this->put( $base . '/' . $file, $file );
		}
		$all  = array();
		$walk = new FileWalk( $base );
		$this->assertTrue( $walk->run( '', static function ( string $path, string $rel ) use ( &$all ): void { $all[] = $rel; }, static fn(): bool => false ) );
		$this->assertSame( array( 'A.txt', 'a/1.php', 'a/2.php', 'a/m/5.txt', 'a/z/9.txt', 'b.txt', 'c/x.txt' ), $all );

		// Stop every two files and resume from the cursor: same files, same order, no repeats.
		$seen   = array();
		$cursor = '';
		$runs   = 0;
		do {
			$walk = new FileWalk( $base );
			$done = $walk->run( $cursor, static function ( string $path, string $rel ) use ( &$seen ): void { $seen[] = $rel; }, static fn(): bool => $walk->files >= 2 );
			$cursor = $walk->cursor;
			++$runs;
		} while ( ! $done && $runs < 20 );
		$this->assertSame( $all, $seen );
		$this->assertSame( 4, $runs );

		// The file at the cursor was deleted in between: the walk continues after where it was.
		wp_delete_file( $base . '/a/2.php' );
		$rest = array();
		( new FileWalk( $base ) )->run( 'a/2.php', static function ( string $path, string $rel ) use ( &$rest ): void { $rest[] = $rel; }, static fn(): bool => false );
		$this->assertSame( array( 'a/m/5.txt', 'a/z/9.txt', 'b.txt', 'c/x.txt' ), $rest );
	}

	public function test_core_and_plugin_files_are_verified_with_coverage(): void {
		$core                                  = self::core_md5();
		$core['wp-includes/version.php']       = md5( 'published version.php' );
		$core['wp-admin/ss-gone.php']          = md5( 'deleted' );
		$plugin                                = $this->fake_plugin();
		$extra_core                            = $this->put( ABSPATH . WPINC . '/ss-extra.php', '<?php eval(base64_decode("ZWNobyAxOw=="));' );
		$this->put( ABSPATH . WPINC . '/ss-notes.txt', 'notes' );
		$this->put( ABSPATH . 'ss-root.php', '<?php echo 1;' );

		$report = $this->verifier( $core, array( 'ss-fake' => $plugin ) )->run_all();
		$titles = self::by_title( $report );
		$cov    = $report['coverage'];

		$this->assertSame( 'critical', $titles['wp-includes/version.php']['severity'], 'changed core file' );
		$this->assertSame( 'critical', $titles[ 'Suspicious code in ' . WPINC . '/ss-extra.php' ]['severity'], 'added PHP in wp-includes' );
		$this->assertSame( 'warning', $titles[ WPINC . '/ss-notes.txt' ]['severity'], 'added non-PHP file in a core folder' );
		$this->assertSame( 'warning', $titles['ss-root.php']['severity'], 'unknown PHP in the WordPress folder' );
		$this->assertSame( 'notice', $titles['WordPress: 1 published file is missing']['severity'] );
		$this->assertSame( 'problems', $cov['core:wordpress']['status'] );
		$this->assertSame( 1, $cov['core:wordpress']['modified'] );
		$this->assertSame( 3, $cov['core:wordpress']['extra'] );
		$this->assertGreaterThan( 1000, $cov['core:wordpress']['files'] );

		$this->assertSame( 'warning', $titles['wp-content/plugins/ss-fake/inc/helpers.php']['severity'] ?? null, 'changed plugin file' );
		$this->assertSame( 'critical', $titles['Suspicious code in wp-content/plugins/ss-fake/inc/evil.php']['severity'], 'added PHP with malware traits' );
		$this->assertArrayNotHasKey( 'wp-content/plugins/ss-fake/cache/data.json', $titles, 'plugins may create non-PHP files' );
		$this->assertSame( 'SS Fake: 2 published files are missing', $titles['SS Fake: 2 published files are missing']['title'] );
		$this->assertSame( array( 'problems', 3, 1, 1 ), array( $cov['plugin:ss-fake']['status'], $cov['plugin:ss-fake']['files'], $cov['plugin:ss-fake']['modified'], $cov['plugin:ss-fake']['extra'] ) );

		$this->assertSame( array( 'unverifiable', 'not_published' ), array( $cov['plugin:akismet']['status'], $cov['plugin:akismet']['reason'] ) );
		$this->assertSame( array( 'unverifiable', 'single_file' ), array( $cov['single:hello.php']['status'], $cov['single:hello.php']['reason'] ) );
		$themes = array_filter( $cov, static fn( array $c ): bool => 'theme' === $c['type'] );
		$this->assertNotEmpty( $themes );
		$this->assertSame( array( 'theme' ), array_values( array_unique( array_column( $themes, 'reason' ) ) ), 'themes cannot be verified' );
		$this->assertNotEmpty( $report['new'] );
		$this->assertNull( FileIntegrity::state(), 'pass finished' );

		// A second pass: nothing new, checksums come from the cache.
		$this->asked = array();
		$again       = $this->verifier( $core, array( 'ss-fake' => $plugin ) )->run_all();
		$this->assertSame( array(), $again['new'] );
		$this->assertSame( array(), $this->asked, 'published checksums are cached' );

		// Approving a changed plugin file quiets it until it changes again.
		$id = $titles['wp-content/plugins/ss-fake/inc/helpers.php']['id'];
		$this->assertNotNull( IntegrityScanner::approve( $id, 1 ) );
		$this->assertSame( 'ok', self::by_title( (array) FileIntegrity::report() )['wp-content/plugins/ss-fake/inc/helpers.php']['severity'] );
		$this->assertSame( 'ok', self::by_title( $this->verifier( $core, array( 'ss-fake' => $plugin ) )->run_all() )['wp-content/plugins/ss-fake/inc/helpers.php']['severity'] );
		file_put_contents( WP_PLUGIN_DIR . '/ss-fake/inc/helpers.php', "<?php\n// changed again\n" );
		$this->assertSame( 'warning', self::by_title( $this->verifier( $core, array( 'ss-fake' => $plugin ) )->run_all() )['wp-content/plugins/ss-fake/inc/helpers.php']['severity'] );
		unset( $extra_core );
	}

	public function test_files_saved_under_cut_off_names_are_one_damaged_install_finding(): void {
		$core    = self::core_md5();
		$long    = 'wp-includes/ss-long-' . str_repeat( 'x', 70 ) . '/SomeVeryLongClassNameInterface.php';
		$fake    = 'wp-includes/ss-long-' . str_repeat( 'y', 70 ) . '/AnotherVeryLongClassNameInterface.php';
		$content = "<?php\ninterface SsLong {}\n";
		$core[ $long ] = md5( $content );
		$core[ $fake ] = md5( $content );
		// The official file under a shortened name, as some unpacking tools leave it.
		$this->put( ABSPATH . substr( $long, 0, 100 ), $content );
		// A shortened name with other content is not excused.
		$this->put( ABSPATH . substr( $fake, 0, 100 ), '<?php eval(base64_decode("ZWNobyAxOw=="));' );

		$report = $this->verifier( $core, array() )->run_all();
		$titles = self::by_title( $report );
		$cov    = $report['coverage']['core:wordpress'];
		$this->assertSame( 'warning', $titles['WordPress: 1 file was saved under a cut-off name']['severity'] );
		$this->assertStringContainsString( $long, $titles['WordPress: 1 file was saved under a cut-off name']['detail'] );
		$this->assertArrayNotHasKey( substr( $long, 0, 100 ), $titles, 'not reported as an added file' );
		$this->assertSame( 1, $cov['truncated_total'] );
		$this->assertSame( 1, $cov['missing_total'], 'only the file without an intact copy is missing' );
		$this->assertSame( 1, $cov['extra'] );
		$this->assertSame( 'critical', $titles[ 'Suspicious code in ' . substr( $fake, 0, 100 ) ]['severity'] );
	}

	public function test_small_slices_resume_to_the_same_result(): void {
		$core   = self::core_md5();
		$core['wp-includes/load.php'] = md5( 'changed' );
		$plugin = $this->fake_plugin();
		$this->put( ABSPATH . 'wp-admin/includes/ss-added.php', '<?php echo 1;' );

		$whole = $this->verifier( $core, array( 'ss-fake' => $plugin ) )->run_all();

		$sliced = $this->verifier( $core, array( 'ss-fake' => $plugin ), 150 );
		$sliced->start( true );
		$runs = 0;
		do {
			$result = $sliced->step( 0.0 );
			++$runs;
			if ( ! $result['done'] ) {
				$this->assertNotNull( FileIntegrity::state(), 'position kept between runs' );
			}
		} while ( ! $result['done'] && $runs < 500 );
		$this->assertTrue( $result['done'] );
		$this->assertGreaterThan( 5, $runs, 'the pass was really split' );
		$this->assertSame( $runs, $result['report']['runs'] );

		$ids = static fn( array $r ): array => array_values( array_unique( array_column( (array) $r['findings'], 'id' ) ) );
		$this->assertEqualsCanonicalizing( $ids( $whole ), $ids( $result['report'] ) );
		$this->assertSame( count( $whole['findings'] ), count( $result['report']['findings'] ), 'nothing reported twice' );
		$this->assertSame( $whole['hashed'], $result['report']['hashed'] );
	}

	public function test_unreachable_wordpress_org_is_reported_and_retried(): void {
		$plugin = $this->fake_plugin();
		$report = $this->verifier( array(), array( 'ss-fake' => $plugin ), 200, true )->run_all();
		$this->assertSame( array( 'unverifiable', 'fetch_failed' ), array( $report['coverage']['plugin:ss-fake']['status'], $report['coverage']['plugin:ss-fake']['reason'] ) );
		$this->assertSame( 'fetch_failed', $report['coverage']['core:wordpress']['reason'] );

		$report = $this->verifier( self::core_md5(), array( 'ss-fake' => $plugin ) )->run_all();
		$this->assertSame( 'problems', $report['coverage']['plugin:ss-fake']['status'], 'a failed download is not cached' );
		$this->assertSame( 'verified', $report['coverage']['core:wordpress']['status'] );
	}

	public function test_only_one_slice_runs_at_a_time(): void {
		$other = new \wpdb( DB_USER, DB_PASSWORD, DB_NAME, DB_HOST );
		$name  = new \ReflectionMethod( \SentinelShield\Support\Mutex::class, 'db_name' );
		$name->setAccessible( true );
		$other->get_var( $other->prepare( 'SELECT GET_LOCK(%s, 0)', $name->invoke( null, 'integrity_scan' ) ) );
		$verifier = $this->verifier( self::core_md5(), array() );
		$verifier->start( true );
		$result = $verifier->step( 5.0 );
		$this->assertTrue( $result['busy'] );
		$this->assertSame( 0, (int) FileIntegrity::state()['runs'] );
		$other->close();
	}

	public function test_malware_scan_reports_coverage_and_resumes_the_uploads_walk(): void {
		$uploads = wp_get_upload_dir()['basedir'];
		$shells  = array();
		for ( $i = 0; $i < 12; $i++ ) {
			$shells[] = $this->put( sprintf( '%s/ss-resume/%02d/shell.php', $uploads, $i ), '<?php echo ' . $i . ';' );
		}
		$this->put( $uploads . '/ss-resume/big.php', '<?php // ' . str_repeat( 'x', IntegrityScanner::max_read() + 10 ) );
		$c       = Plugin::instance()->container();
		$scanner = new IntegrityScanner( $c->get( AdminRegistry::class ), $c->get( EventRepository::class ), $c->get( Settings::class ), 5 );

		$runs    = 0;
		$reports = array();
		do {
			$reports[] = $scanner->run();
			++$runs;
		} while ( empty( end( $reports )['complete'] ) && $runs < 1000 );
		$final = end( $reports );
		$this->assertTrue( $final['complete'] );
		$this->assertGreaterThan( 2, $runs );
		$this->assertFalse( $reports[0]['complete'] );
		$this->assertNotNull( $reports[0]['coverage']['uploads']['cursor'] ?? null );

		$titles = array_column( $final['findings'], 'title' );
		foreach ( $shells as $shell ) {
			$this->assertContains( wp_normalize_path( str_replace( ABSPATH, '', $shell ) ) . ': not reviewed yet', $titles, 'every file reached, findings carried across runs' );
		}
		$this->assertSame( count( $titles ), count( array_unique( array_column( $final['findings'], 'id' ) ) ), 'nothing listed twice' );
		$partial = implode( ',', array_merge( ...array_map( static fn( array $r ): array => (array) $r['coverage']['partial'], $reports ) ) );
		$this->assertStringContainsString( 'ss-resume/big.php', $partial, 'large files are reported as read only partly' );
		$this->assertNull( get_site_option( IntegrityScanner::UPLOADS_STATE, null ), 'state cleared at the end' );

		// Unlimited (WP-CLI): one run covers everything.
		$this->assertTrue( $scanner->run( true )['complete'] );
	}
}
