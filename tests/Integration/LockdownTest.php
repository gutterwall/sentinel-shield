<?php
/**
 * Malware lockdown: administrator lock, hardening filters and the SC malware scan.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Tests\Integration;

use SentinelShield\Lockdown\AdminRegistry;
use SentinelShield\Lockdown\Hardening;
use SentinelShield\Lockdown\IntegrityScanner;
use SentinelShield\Lockdown\OutboundGuard;
use SentinelShield\Lockdown\UploadGuard;
use SentinelShield\Plugin;
use SentinelShield\Repository\EventRepository;
use SentinelShield\Settings;

/**
 * A login hook defined in a file that is created inside uploads during the test.
 */
final class LockdownTest extends \WP_UnitTestCase {

	use AdminUsers;

	/**
	 * Files created by a test, removed in tear_down.
	 *
	 * @var list<string>
	 */
	private array $created = array();

	/**
	 * Hardening instance under test.
	 *
	 * @var Hardening|null
	 */
	private ?Hardening $hardening = null;

	public function set_up(): void {
		parent::set_up();
		delete_site_option( AdminRegistry::OPTION );
		delete_site_option( IntegrityScanner::REPORT_OPTION );
		delete_site_option( IntegrityScanner::BASELINE_OPTION );
		global $wpdb;
		$wpdb->query( $wpdb->prepare( 'DELETE FROM %i', Plugin::instance()->container()->get( EventRepository::class )->table() ) );
		// The plugin registered its own instance at boot with default settings; test one instance at a time.
		self::unhook( Plugin::instance()->container()->get( Hardening::class ) );
	}

	public static function tear_down_after_class(): void {
		Plugin::instance()->container()->get( Hardening::class )->register();
		parent::tear_down_after_class();
	}

	public function tear_down(): void {
		if ( null !== $this->hardening ) {
			self::unhook( $this->hardening );
		}
		foreach ( array_reverse( $this->created ) as $path ) {
			is_dir( $path ) ? rmdir( $path ) : wp_delete_file( $path );
		}
		delete_site_option( Settings::OPTION );
		Plugin::instance()->container()->get( Settings::class )->refresh();
		unset( $_REQUEST['_wpnonce'] );
		parent::tear_down();
	}

	/**
	 * Removes every hook a Hardening instance may have added.
	 *
	 * @param Hardening $h Instance.
	 */
	private static function unhook( Hardening $h ): void {
		remove_filter( 'map_meta_cap', array( $h, 'map_meta_cap' ), PHP_INT_MAX );
		remove_filter( 'pre_http_request', array( $h, 'filter_http' ), 0 );
		remove_action( 'update_user_meta', array( $h, 'before_caps_change' ) );
		remove_action( 'updated_user_meta', array( $h, 'after_caps_change' ) );
		remove_action( 'added_user_meta', array( $h, 'after_caps_change' ) );
		remove_action( 'granted_super_admin', array( $h, 'on_super_admin' ) );
		remove_filter( 'pre_update_option_active_plugins', array( $h, 'keep_active' ) );
		remove_filter( 'pre_update_site_option_active_sitewide_plugins', array( $h, 'keep_active_network' ) );
		remove_action( 'deactivate_plugin', array( $h, 'guard_deactivate' ), 0 );
		remove_action( 'delete_plugin', array( $h, 'guard_delete' ), 0 );
		remove_filter( 'wp_handle_upload_prefilter', array( UploadGuard::class, 'filter' ) );
		remove_filter( 'wp_handle_sideload_prefilter', array( UploadGuard::class, 'filter' ) );
	}

	/**
	 * Saves lockdown settings and returns a freshly registered Hardening.
	 *
	 * @param array<string, bool> $lockdown Settings under lockdown.*.
	 */
	private function harden( array $lockdown, ?AdminRegistry $registry = null ): Hardening {
		update_site_option( Settings::OPTION, array( 'lockdown' => $lockdown ) );
		$c        = Plugin::instance()->container();
		$settings = $c->get( Settings::class );
		$settings->refresh();
		$this->hardening = new Hardening( $settings, $registry ?? new AdminRegistry(), $c->get( EventRepository::class ), static fn(): string => '203.0.113.9' );
		$this->hardening->register();
		return $this->hardening;
	}

	/**
	 * Creates an administrator the way SC does: straight into the tables, no hooks.
	 */
	private function sql_admin( string $login ): int {
		global $wpdb;
		$wpdb->insert(
			$wpdb->users,
			array(
				'user_login'      => $login,
				'user_nicename'   => $login,
				'user_pass'       => wp_hash_password( 'x' ),
				'user_email'      => $login . '@example.test',
				'user_registered' => gmdate( 'Y-m-d H:i:s' ),
				'display_name'    => $login,
			)
		);
		$id = (int) $wpdb->insert_id;
		$wpdb->insert(
			$wpdb->usermeta,
			array(
				'user_id'    => $id,
				'meta_key'   => $wpdb->get_blog_prefix() . 'capabilities',
				'meta_value' => serialize( array( 'administrator' => true ) ),
			)
		);
		if ( is_multisite() ) {
			// On a network the takeover goes into the super admin list, also without hooks.
			$admins   = (array) get_site_option( 'site_admins', array() );
			$admins[] = $login;
			$wpdb->update( $wpdb->sitemeta, array( 'meta_value' => serialize( $admins ) ), array( 'meta_key' => 'site_admins', 'site_id' => get_current_network_id() ) );
			wp_cache_delete( get_current_network_id() . ':site_admins', 'site-options' );
		}
		clean_user_cache( $id );
		return $id;
	}

	/**
	 * Writes a file and remembers it for cleanup.
	 */
	private function put( string $path, string $content ): string {
		if ( ! is_dir( dirname( $path ) ) ) {
			mkdir( dirname( $path ), 0777, true );
			$this->created[] = dirname( $path );
		}
		file_put_contents( $path, $content );
		$this->created[] = $path;
		return $path;
	}

	/**
	 * Findings of one check from a fresh scan.
	 *
	 * @param array<string, mixed> $report Report.
	 * @param string               $check  Check slug.
	 * @return list<array<string, mixed>>
	 */
	private static function of( array $report, string $check ): array {
		return array_values( array_filter( $report['findings'], static fn( array $f ): bool => $f['check'] === $check ) );
	}

	private function scanner(): IntegrityScanner {
		$c = Plugin::instance()->container();
		return new IntegrityScanner( new AdminRegistry(), $c->get( EventRepository::class ), $c->get( Settings::class ) );
	}

	public function test_admin_lock_strips_unapproved_admins_and_never_locks_everyone(): void {
		$approved = self::create_admin();
		$rogue    = $this->sql_admin( 'sc_rogue' );
		$this->harden( array( 'admin_lock' => true ) );

		$this->assertTrue( user_can( $rogue, 'manage_options' ), 'No approvals yet: the lock must not apply.' );

		$registry = new AdminRegistry();
		$registry->approve( $approved, 0 );
		$this->hardening = null;
		$this->harden( array( 'admin_lock' => true ) );
		$this->assertTrue( user_can( $approved, 'manage_options' ) );
		$this->assertTrue( user_can( $approved, 'activate_plugins' ) );
		$this->assertFalse( user_can( $rogue, 'manage_options' ) );
		$this->assertFalse( user_can( $rogue, 'edit_users' ) );
		$this->assertFalse( user_can( $rogue, 'activate_plugins' ) );
		$this->assertTrue( user_can( $rogue, 'read' ) );

		// Renaming an approved account withdraws the approval.
		global $wpdb;
		$wpdb->update( $wpdb->users, array( 'user_login' => 'renamed_admin' ), array( 'ID' => $approved ) );
		clean_user_cache( $approved );
		$this->assertFalse( ( new AdminRegistry() )->is_approved( get_userdata( $approved ) ) );
	}

	public function test_hidden_admin_is_detected_and_not_auto_approved(): void {
		$visible = self::create_admin();
		$rogue   = $this->sql_admin( 'sc_hidden' );
		$hide    = static function ( \WP_User_Query $q ) use ( $rogue ): void {
			global $wpdb;
			$q->query_where .= $wpdb->prepare( " AND {$wpdb->users}.ID != %d", $rogue );
		};
		add_action( 'pre_user_query', $hide );

		$registry = new AdminRegistry();
		$users    = array_column( $registry->privileged_users(), null, 'id' );
		$this->assertTrue( $users[ $rogue ]['hidden'] );
		$this->assertFalse( $users[ $visible ]['hidden'] );

		$registry->approve_visible( $visible );
		$this->assertTrue( $registry->is_approved( get_userdata( $visible ) ) );
		$this->assertFalse( $registry->is_approved( get_userdata( $rogue ) ) );

		$admins = self::of( $this->scanner()->run(), 'admins' );
		remove_action( 'pre_user_query', $hide );
		$this->assertSame( 'critical', $admins[0]['severity'] );
		$this->assertStringContainsString( 'sc_hidden', $admins[0]['title'] );
	}

	public function test_file_editor_and_install_caps_are_removed(): void {
		$admin = self::create_admin();
		$this->assertTrue( user_can( $admin, 'install_plugins' ) || is_multisite() );
		$this->harden(
			array(
				'disable_file_editor' => true,
				'block_installs'      => true,
			)
		);
		foreach ( array_merge( Hardening::EDITOR_CAPS, Hardening::INSTALL_CAPS ) as $cap ) {
			$this->assertFalse( user_can( $admin, $cap ), $cap );
		}
		$this->assertTrue( user_can( $admin, 'update_plugins' ) || is_multisite(), 'Updates keep working.' );
		$this->assertTrue( user_can( $admin, 'manage_options' ) );
	}

	public function test_upload_guard_rejects_scripts(): void {
		foreach ( array( 'shell.php', 'x.PHP5', 'shell.php.jpg', 'a.phtml', 'b.phar', '.htaccess', '.user.ini', 'php.ini', 'c.pht' ) as $name ) {
			$this->assertNotNull( UploadGuard::dangerous_name( $name ), $name );
		}
		foreach ( array( 'photo.jpg', 'report.pdf', 'php-guide.txt', 'philosophy.png' ) as $name ) {
			$this->assertNull( UploadGuard::dangerous_name( $name ), $name );
		}
		$tmp = $this->put( get_temp_dir() . 'ss-up-' . wp_generate_password( 6, false ) . '.tmp', "GIF89a\n<?php system(\$_GET['c']); ?>" );
		$out = UploadGuard::filter(
			array(
				'name'     => 'cat.gif',
				'tmp_name' => $tmp,
				'error'    => 0,
			)
		);
		$this->assertStringContainsString( 'contains PHP code', (string) $out['error'] );

		$binary = $this->put( get_temp_dir() . 'ss-up-' . wp_generate_password( 6, false ) . '.tmp', "\x89PNG\0\0<?=" );
		$this->assertFalse( UploadGuard::contains_php( $binary ), 'Short tags in binary files are coincidence.' );
	}

	public function test_uploads_htaccess_is_added_and_removed_cleanly(): void {
		$path     = UploadGuard::htaccess_path();
		$existing = is_file( $path ) ? (string) file_get_contents( $path ) : null;
		file_put_contents( $path, "# site rule\nOptions -Indexes\n" );
		try {
			$this->assertTrue( UploadGuard::sync_htaccess( true ) );
			$this->assertTrue( UploadGuard::htaccess_installed() );
			$this->assertStringContainsString( 'Require all denied', (string) file_get_contents( $path ) );
			$this->assertTrue( UploadGuard::sync_htaccess( false ) );
			$this->assertFalse( UploadGuard::htaccess_installed() );
			$this->assertStringContainsString( 'Options -Indexes', (string) file_get_contents( $path ), 'Other rules are kept.' );
		} finally {
			null === $existing ? wp_delete_file( $path ) : file_put_contents( $path, $existing );
		}
	}

	public function test_blockchain_rpc_is_blocked_by_host_and_by_body(): void {
		$this->assertSame( 'gateway llamarpc.com', OutboundGuard::match( 'https://eth.llamarpc.com/' ) );
		$this->assertSame( 'gateway bsc-dataseed1.binance.org', OutboundGuard::match( 'https://bsc-dataseed1.binance.org/' ) );
		$this->assertSame( 'JSON-RPC eth_call', OutboundGuard::match( 'https://rpc.unknown-gateway.example/', array( 'body' => '{"jsonrpc":"2.0","method":"eth_call","params":[]}' ) ) );
		$this->assertNull( OutboundGuard::match( 'https://api.wordpress.org/plugins/update-check/1.1/', array( 'body' => array( 'plugins' => '{}' ) ) ) );
		$this->assertNull( OutboundGuard::match( 'https://notpublicnode.com.example/' ) );

		$this->harden( array( 'block_chain_rpc' => true ) );
		$result = wp_remote_post( 'https://ethereum-rpc.publicnode.com/', array( 'body' => '{}' ) );
		$this->assertWPError( $result );
		$this->assertSame( 'sentinel_shield_blocked_outbound', $result->get_error_code() );
		$events = Plugin::instance()->container()->get( EventRepository::class )->query( array( 'event' => 'lockdown_outbound' ) );
		$this->assertStringContainsString( 'LockdownTest.php', $events['rows'][0]['reason'] ?? wp_json_encode( $events ), 'The log names the calling file.' );
	}

	public function test_self_protection_keeps_plugin_active_unless_admin_deactivates(): void {
		$h    = $this->harden( array( 'protect_self' => true ) );
		$base = plugin_basename( SENTINEL_SHIELD_FILE );

		$this->assertContains( $base, $h->keep_active( array( 'other/other.php' ), array( $base, 'other/other.php' ) ), 'Code with no admin cannot drop it.' );
		$events = Plugin::instance()->container()->get( EventRepository::class );
		$this->assertSame( 1, $events->count_since( array( 'lockdown_tamper' ), time() - 60 ) );

		wp_set_current_user( self::create_admin() );
		$this->assertContains( $base, $h->keep_active( array(), array( $base ) ), 'An admin without the Plugins screen nonce cannot either.' );
		$_REQUEST['_wpnonce'] = wp_create_nonce( 'deactivate-plugin_' . $base );
		$this->assertNotContains( $base, $h->keep_active( array(), array( $base ) ), 'The Plugins screen can.' );

		unset( $_REQUEST['_wpnonce'] );
		$this->expectException( \WPDieException::class );
		$h->guard_deactivate( $base );
	}

	public function test_new_administrator_is_logged_and_emailed(): void {
		reset_phpmailer_instance();
		$this->harden( array( 'alert_admin_changes' => true ) );
		$user = self::factory()->user->create( array( 'role' => 'subscriber' ) );
		( new \WP_User( $user ) )->set_role( 'editor' );
		self::make_admin( $user );
		( new \WP_User( $user ) )->add_cap( 'some_extra_cap' );

		$events = Plugin::instance()->container()->get( EventRepository::class );
		$this->assertSame( 1, $events->count_since( array( 'lockdown_admin_added' ), time() - 60 ), 'Only becoming an admin alerts, once.' );
		$sent = tests_retrieve_phpmailer_instance()->get_sent();
		$this->assertStringContainsString( 'New administrator account', $sent->subject );
		$this->assertStringContainsString( get_userdata( $user )->user_login, $sent->body );
	}

	public function test_signatures(): void {
		$this->assertSame( 'critical', IntegrityScanner::worst( IntegrityScanner::signatures( '<?php // SC_BEGIN' ), 'notice' ) );
		$this->assertSame( 'critical', IntegrityScanner::worst( IntegrityScanner::signatures( '<?php eval(gzinflate(base64_decode($p)));' ), 'notice' ) );
		$this->assertSame( 'critical', IntegrityScanner::worst( IntegrityScanner::signatures( '<?php $s = shmop_open(0xff3, "c", 0644, 100);' ), 'notice' ) );
		$this->assertSame( 'critical', IntegrityScanner::worst( IntegrityScanner::signatures( '{"method":"eth_call"}' ), 'notice' ) );
		$this->assertSame( array(), IntegrityScanner::signatures( "<?php\n// Redis object cache drop-in.\nfunction wp_cache_get( \$k ) { return false; }" ) );
		$this->assertTrue( IntegrityScanner::looks_random( 'a3f9c2b18e' ) );
		$this->assertTrue( IntegrityScanner::looks_random( 'k7xq2mz9wp4r' ) );
		$this->assertFalse( IntegrityScanner::looks_random( 'wp_version_check' ) );
		$this->assertFalse( IntegrityScanner::looks_random( 'woocommerce_cleanup_sessions' ) );
	}

	public function test_scan_finds_sc_persistence_points_and_approval_tracks_changes(): void {
		$content = WP_CONTENT_DIR;
		$uploads = wp_get_upload_dir()['basedir'];
		$marker  = "<?php\n/* SC_BEGIN a1 */ if ( ! defined( 'SC_AUTO_PREPEND' ) ) { define( 'SC_AUTO_PREPEND', 1 ); }\n/* SC_END a1 */\n";

		$this->put( $content . '/.c1b1test.php', $marker );
		$this->put( $content . '/c1b1d00d.php', "<?php if ( is_file( __DIR__ . '/.c1b1test.php' ) ) { include __DIR__ . '/.c1b1test.php'; }\n" );
		$this->put( ABSPATH . '.user.ini', "auto_prepend_file = \"{$content}/c1b1d00d.php\"\n" );
		$this->put( WPMU_PLUGIN_DIR . '/hyper-engine-kit.php', $marker );
		$this->put( WP_PLUGIN_DIR . '/hyper-engine-kit/hyper-engine-kit.php', "<?php\n/*\nPlugin Name: Hyper Engine Kit\n*/\n" . substr( $marker, 6 ) );
		$this->put( $content . '/advanced-cache.php', "<?php\n" . '$p = "' . base64_encode( gzcompress( str_repeat( 'payload ', 900 ) ) ) . "\";\n eval( gzuncompress( base64_decode( \$p ) ) );\n" );
		$this->put( $uploads . '/3f9a0c2e7b.zip', 'PK' );
		$shell = $this->put( $uploads . '/2026/10/shell-ss.php', '<?php echo 1;' );
		$this->put( $uploads . '/2026/10/index.php', '<?php // Silence is golden.' );
		$hook_file = $this->put( $uploads . '/ss-capture.php', "<?php\nfunction ss_test_capture( \$u ) { return \$u; }\n" );
		require_once $hook_file;
		add_filter( 'authenticate', 'ss_test_capture', 1 );
		$hide = static function ( array $plugins ): array {
			unset( $plugins['hyper-engine-kit/hyper-engine-kit.php'] );
			return $plugins;
		};
		add_filter( 'all_plugins', $hide );
		wp_clean_plugins_cache( false );

		add_option( 'wp_x7k2q9m4', base64_encode( gzcompress( random_bytes( 30000 ) ) ), '', false );
		add_option( 'sc_beacon_state', 'x' );
		wp_schedule_single_event( time() + 3600, 'q8z3k1x9v2m7' );
		wp_schedule_single_event( time() + 3600, 'ss_test_upload_job' );
		add_action( 'ss_test_upload_job', 'ss_test_capture' );

		$report = $this->scanner()->run();
		remove_filter( 'authenticate', 'ss_test_capture', 1 );
		remove_filter( 'all_plugins', $hide );
		wp_clear_scheduled_hook( 'q8z3k1x9v2m7' );
		wp_clear_scheduled_hook( 'ss_test_upload_job' );

		$worst = static function ( string $check ) use ( $report ): string {
			$list = self::of( $report, $check );
			return $list ? IntegrityScanner::worst( array_map( static fn( array $f ): array => array( '', $f['severity'] ), $list ), 'ok' ) : 'none';
		};
		$this->assertSame( 'critical', $worst( 'prepend' ) );
		$this->assertSame( 'critical', $worst( 'dropins' ) );
		$this->assertSame( 'critical', $worst( 'mu_plugins' ) );
		$this->assertStringContainsString( 'also installed as a regular plugin', self::of( $report, 'mu_plugins' )[0]['detail'] );
		$this->assertSame( 'critical', $worst( 'hidden_plugins' ) );
		$this->assertSame( 'critical', $worst( 'stray_files' ) );
		$this->assertSame( 'critical', $worst( 'options' ) );
		$this->assertSame( 'critical', $worst( 'cron' ) );
		$this->assertSame( 'critical', $worst( 'hooks' ) );
		$titles = implode( "\n", array_column( $report['findings'], 'title' ) );
		$this->assertStringContainsString( '3f9a0c2e7b.zip', $titles );
		$this->assertStringContainsString( 'sc_beacon_state', $titles );
		$this->assertStringContainsString( 'q8z3k1x9v2m7', $titles );
		$this->assertStringNotContainsString( '2026/10/index.php', $titles, 'Silence-is-golden placeholders are ignored.' );
		$this->assertContains( self::of( $report, 'prepend' )[0]['id'], $report['new'] );

		// Approving the PHP file in uploads quiets it until the file changes.
		$finding = array_values( array_filter( self::of( $report, 'stray_files' ), static fn( array $f ): bool => str_contains( $f['title'], 'shell-ss.php' ) ) )[0];
		$this->assertSame( 'warning', $finding['severity'] );
		$this->assertNotNull( IntegrityScanner::approve( $finding['id'], 1 ) );
		$again = array_column( $this->scanner()->run()['findings'], null, 'id' );
		$this->assertSame( 'ok', $again[ $finding['id'] ]['severity'] );
		$this->assertNotContains( $finding['id'], (array) IntegrityScanner::report()['new'] );
		file_put_contents( $shell, '<?php echo 2;' );
		$again = array_column( $this->scanner()->run()['findings'], null, 'id' );
		$this->assertSame( 'warning', $again[ $finding['id'] ]['severity'], 'A changed file needs approving again.' );
	}

	public function test_database_triggers_on_user_tables_are_critical(): void {
		global $wpdb;
		// DDL commits the test transaction, so this test creates nothing else.
		$wpdb->query( "CREATE TRIGGER ss_test_trg AFTER DELETE ON {$wpdb->users} FOR EACH ROW SET @ss_x = 1" );
		try {
			$this->assertSame( '', $wpdb->last_error );
			$found = self::of( $this->scanner()->run(), 'triggers' );
		} finally {
			$wpdb->query( 'DROP TRIGGER IF EXISTS ss_test_trg' );
		}
		$this->assertSame( 'critical', $found[0]['severity'] );
		$this->assertStringContainsString( 'ss_test_trg', $found[0]['title'] );
	}

	public function test_parses_the_wp_config_admin_list(): void {
		$this->assertSame(
			array(
				array( 'login' => 'admin', 'id' => 1 ),
				array( 'login' => 'Jane', 'id' => null ),
				array( 'login' => 'bob', 'id' => 7 ),
			),
			AdminRegistry::parse( 'admin#1, Jane , #3, , bob # 7' )
		);
		$this->assertSame( array( array( 'login' => 'x', 'id' => 2 ) ), AdminRegistry::parse( array( 'x#2', '' ) ) );
		$this->assertSame( array(), AdminRegistry::parse( '' ) );
	}

	public function test_wp_config_list_replaces_approvals_and_is_always_enforced(): void {
		$keeper = self::create_admin( array( 'user_login' => 'keeper' ) );
		$other  = self::create_admin( array( 'user_login' => 'other' ) );
		define( 'SS_TEST_ADMINS_A', 'KEEPER#' . $keeper . ', ghost' );
		$registry = new AdminRegistry( 'SS_TEST_ADMINS_A' );
		// A database approval for "other" is ignored while the constant is defined.
		( new AdminRegistry() )->approve( $other, $keeper );

		// The lock applies although the setting is off.
		$this->harden( array( 'admin_lock' => false ), $registry );
		$this->assertTrue( user_can( $keeper, 'manage_options' ), 'listed admin (case-insensitive login, pinned ID) keeps rights' );
		$this->assertFalse( user_can( $other, 'manage_options' ), 'unlisted admin is locked' );
		$this->assertTrue( user_can( $other, 'read' ) );
		$this->assertTrue( user_can( $other, 'edit_user', $other ), 'own profile stays reachable' );
		$this->assertFalse( user_can( $other, 'edit_user', $keeper ) );
		$this->assertTrue( $registry->enforced( false ) );

		$this->assertFalse( $registry->approve( $other, $keeper ), 'database approvals cannot be changed' );
		$this->assertFalse( $registry->revoke( $keeper ) );
		$this->assertSame( 0, $registry->approve_visible( $keeper ) );

		$states = array_column( $registry->fixed_report(), 'state', 'entry' );
		$this->assertSame( array( 'KEEPER#' . $keeper => 'ok', 'ghost' => 'missing' ), $states );

		// The scan warns that an unmatched login could be claimed.
		$scanner = new IntegrityScanner( $registry, Plugin::instance()->container()->get( EventRepository::class ), Plugin::instance()->container()->get( Settings::class ) );
		$titles  = array_column( $scanner->run()['findings'], 'title' );
		$this->assertContains( 'SENTINEL_SHIELD_ADMINS entry "ghost" matches no account', $titles );
		$this->assertNotEmpty( preg_grep( '/waiting for approval: other /', $titles ) );

		// Which is exactly the risk: an unpinned entry approves whoever registers that login.
		$ghost = self::create_admin( array( 'user_login' => 'ghost' ) );
		$this->assertTrue( user_can( $ghost, 'manage_options' ) );
	}

	public function test_pinned_entry_rejects_a_re_registered_login(): void {
		$admin = self::create_admin( array( 'user_login' => 'pinned' ) );
		define( 'SS_TEST_ADMINS_B', 'pinned#' . ( $admin + 1000 ) );
		$registry = new AdminRegistry( 'SS_TEST_ADMINS_B' );
		$this->harden( array(), $registry );
		$this->assertFalse( user_can( $admin, 'manage_options' ) );
		$this->assertSame( 'id_mismatch', $registry->fixed_report()[0]['state'] );
	}

	public function test_empty_wp_config_list_locks_every_administrator(): void {
		$admin = self::create_admin();
		define( 'SS_TEST_ADMINS_C', '' );
		$registry = new AdminRegistry( 'SS_TEST_ADMINS_C' );
		$this->harden( array(), $registry );
		$this->assertTrue( $registry->is_fixed() );
		$this->assertFalse( user_can( $admin, 'manage_options' ) );
	}
}
