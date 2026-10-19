<?php
/**
 * Every admin operation, run by an administrator: it does what it says, and
 * says so.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Tests\Integration;

use SentinelShield\Admin\Actions;
use SentinelShield\Admin\TwoFactorPage;
use SentinelShield\Audit\AuditExporter;
use SentinelShield\Firewall\CloudflareSync;
use SentinelShield\Firewall\RuleCache;
use SentinelShield\Lockdown\AdminRegistry;
use SentinelShield\Net\Cidr;
use SentinelShield\Plugin;
use SentinelShield\Repository\BlockRepository;
use SentinelShield\Repository\LoginAttemptRepository;
use SentinelShield\Settings;
use SentinelShield\Support\DataDir;
use SentinelShield\TwoFactor\Totp;
use SentinelShield\TwoFactor\UserTwoFactor;

/**
 * Review 5 (coverage of authorization paths): the authorization matrix shows
 * who is refused; this runs each operation through to its result for the
 * administrator it is meant for, so the code behind the checks is exercised
 * too (and a handler that broke would show here first).
 */
final class AdminActionsTest extends \WP_UnitTestCase {

	use AdminUsers;

	private int $admin = 0;

	private string $data = '';

	public function private_dir(): string {
		return $this->data;
	}

	public function set_up(): void {
		parent::set_up();
		$c = Plugin::instance()->container();
		global $wpdb;
		$wpdb->query( $wpdb->prepare( 'DELETE FROM %i', $c->get( BlockRepository::class )->table() ) );
		$c->get( RuleCache::class )->flush();
		$this->data = get_temp_dir() . 'ss-actions-' . wp_generate_password( 6, false );
		add_filter( 'sentinel_shield_data_dir', array( $this, 'private_dir' ) );
		$_SERVER['DOCUMENT_ROOT'] = ABSPATH;
		$this->admin              = self::create_admin( array( 'user_pass' => 'right-pass' ) );
		wp_set_current_user( $this->admin );
		// A real login session: identity confirmations are per session.
		$token                       = \WP_Session_Tokens::get_instance( $this->admin )->create( time() + HOUR_IN_SECONDS );
		$_COOKIE[ LOGGED_IN_COOKIE ] = wp_generate_auth_cookie( $this->admin, time() + HOUR_IN_SECONDS, 'logged_in', $token );
		( new Actions( $c ) )->register();
		( new TwoFactorPage( $c ) )->register();
		add_filter( 'wp_redirect', array( self::class, 'stop' ) );
		add_filter( 'pre_http_request', array( self::class, 'offline' ) );
	}

	public function tear_down(): void {
		remove_filter( 'wp_redirect', array( self::class, 'stop' ) );
		remove_filter( 'pre_http_request', array( self::class, 'offline' ) );
		remove_filter( 'sentinel_shield_data_dir', array( $this, 'private_dir' ) );
		foreach ( array_keys( $GLOBALS['wp_filter'] ) as $hook ) {
			if ( is_string( $hook ) && str_starts_with( $hook, 'admin_post_sentinel_shield' ) ) {
				remove_all_actions( $hook );
			}
		}
		exec( 'rm -rf ' . escapeshellarg( $this->data ) );
		foreach ( array( Settings::OPTION, CloudflareSync::TOKEN, CloudflareSync::STATE, DataDir::OPTION, DataDir::ROOT, 'sentinel_shield_welcome' ) as $option ) {
			delete_site_option( $option );
		}
		unset( $_SERVER['DOCUMENT_ROOT'] );
		Plugin::instance()->container()->get( Settings::class )->refresh();
		$_POST    = array();
		$_GET     = array();
		$_REQUEST = array();
		unset( $_COOKIE[ LOGGED_IN_COOKIE ] );
		wp_set_current_user( 0 );
		parent::tear_down();
	}

	/**
	 * @param string $location Redirect target.
	 * @throws RedirectedTo Always.
	 */
	public static function stop( $location ): string {
		throw new RedirectedTo( (string) $location );
	}

	public static function offline(): \WP_Error {
		return new \WP_Error( 'http_request_failed', 'No network in tests.' );
	}

	/**
	 * Runs an admin-post action with a valid nonce; returns where it redirected
	 * and the notices it queued.
	 *
	 * @param string               $action Action (without prefix for the plugin's own).
	 * @param array<string, mixed> $post   Fields.
	 * @param array<string, mixed> $get    Query fields.
	 * @return array{0:string, 1:list<array{0:string, 1:string}>}
	 */
	private function post( string $action, array $post = array(), array $get = array() ): array {
		$hook = str_starts_with( $action, 'sentinel_shield' ) ? $action : 'sentinel_shield_' . $action;
		$_POST            = $post;
		$_POST['_wpnonce'] = wp_create_nonce( $hook );
		$_GET             = $get;
		$_REQUEST         = array_merge( $_GET, $_POST );
		delete_site_transient( 'sentinel_shield_flash_' . get_current_user_id() );
		$where = '';
		try {
			do_action( 'admin_post_' . $hook );
		} catch ( RedirectedTo $e ) {
			$where = $e->getMessage();
		} finally {
			$_POST    = array();
			$_GET     = array();
			$_REQUEST = array();
		}
		$flash = get_site_transient( 'sentinel_shield_flash_' . get_current_user_id() );
		return array( $where, is_array( $flash ) ? $flash : array() );
	}

	/**
	 * The notice types of a result.
	 *
	 * @param array{0:string, 1:list<array{0:string, 1:string}>} $result post() result.
	 * @return list<string>
	 */
	private static function types( array $result ): array {
		return array_column( $result[1], 0 );
	}

	public function test_settings_rules_and_unblocking(): void {
		$c = Plugin::instance()->container();
		$r = $this->post( 'save_settings', array( 'tab' => 'login', 'sentinel_shield' => array( 'login' => array( 'max_failures' => '7' ) ) ) );
		$this->assertContains( 'success', self::types( $r ) );
		$this->assertStringContainsString( 'tab=login', $r[0] );
		$this->assertSame( 7, $c->get( Settings::class )->get( 'login.max_failures' ) );
		$r = $this->post( 'save_settings', array( 'tab' => 'ip_detection', 'sentinel_shield' => array( 'proxy' => array( 'trusted_cidrs' => "10.0.0.0/8\nnot-a-range" ) ) ) );
		$this->assertContains( 'error', self::types( $r ), 'an invalid entry is reported' );

		$this->assertContains( 'success', self::types( $this->post( 'add_rule', array( 'value' => '198.51.100.0/24', 'list_type' => 'block', 'expires_hours' => '2' ) ) ) );
		$this->assertContains( 'error', self::types( $this->post( 'add_rule', array( 'value' => 'not an ip' ) ) ) );
		$rule = $c->get( BlockRepository::class )->find_exact( 'block', Cidr::parse( '198.51.100.0/24' ) );
		$this->assertNotNull( $rule );
		$this->assertNotNull( $rule['expires_at'], 'expires in two hours' );
		$this->assertContains( 'success', self::types( $this->post( 'add_rule', array( 'value' => '203.0.113.5', 'list_type' => 'allow', 'reason' => 'office' ) ) ) );

		$r = $this->post( 'unblock_ip', array( 'ip' => '198.51.100.9' ) );
		$this->assertContains( 'warning', self::types( $r ), 'a range still covers it' );
		$r = $this->post( 'unblock_ip', array( 'ip' => '198.51.100.9', 'include_ranges' => '1' ) );
		$this->assertContains( 'success', self::types( $r ) );
		$this->assertNull( $c->get( BlockRepository::class )->find_exact( 'block', Cidr::parse( '198.51.100.0/24' ) ) );
		$this->assertContains( 'error', self::types( $this->post( 'unblock_ip', array( 'ip' => 'nonsense' ) ) ) );

		$id = (int) $c->get( BlockRepository::class )->add( 'block', Cidr::parse( '192.0.2.44' ), 'x', 'manual' );
		$this->assertContains( 'success', self::types( $this->post( 'delete_rule', array(), array( 'id' => $id ) ) ) );
		$this->assertNull( $c->get( BlockRepository::class )->get( $id ) );

		$r = $this->post( 'import_settings', array( 'sentinel_json_text' => (string) wp_json_encode( array( 'plugin' => 'sentinel-shield', 'settings' => array( 'login' => array( 'max_failures' => 9 ) ) ) ) ) );
		$this->assertContains( 'success', self::types( $r ) );
		$this->assertSame( 9, $c->get( Settings::class )->get( 'login.max_failures' ) );
		$this->assertContains( 'error', self::types( $this->post( 'import_settings', array( 'sentinel_json_text' => '{broken' ) ) ) );
		$this->assertContains( 'error', self::types( $this->post( 'import_rules' ) ), 'no file uploaded' );

		update_site_option( 'sentinel_shield_welcome', 1 );
		$this->post( 'dismiss_welcome' );
		$this->assertFalse( get_site_option( 'sentinel_shield_welcome' ) );
	}

	public function test_tools(): void {
		$c = Plugin::instance()->container();
		$this->assertContains( 'success', self::types( $this->post( 'tool', array( 'tool' => 'test_mode', 'mode' => 'on24' ) ) ) );
		$this->assertTrue( $c->get( Settings::class )->global_test_mode() );
		$this->assertGreaterThan( time(), (int) $c->get( Settings::class )->get( 'general.test_mode_until' ), 'with an end' );
		$this->post( 'tool', array( 'tool' => 'test_mode', 'mode' => 'off' ) );
		$this->assertFalse( $c->get( Settings::class )->global_test_mode() );

		$c->get( BlockRepository::class )->add( 'block', Cidr::parse( '192.0.2.0/24' ), 'sim', 'manual' );
		$c->get( RuleCache::class )->flush();
		$this->post( 'tool', array( 'tool' => 'simulate', 'ip' => '192.0.2.8', 'uri' => '/shop' ) );
		$sim = \SentinelShield\Admin\View::take_result( 'simulate' );
		$this->assertSame( '192.0.2.0/24', $sim['rule'] );
		$this->assertTrue( $sim['enforced'] );

		$this->post( 'tool', array( 'tool' => 'resolve', 'remote_addr' => '10.0.0.5', 'headers' => "X-Forwarded-For: 203.0.113.70\nUser-Agent: x", 'mode' => 'none' ) );
		$this->assertIsArray( \SentinelShield\Admin\View::take_result( 'resolve' ) );

		$this->post( 'tool', array( 'tool' => 'lockout', 'ip' => '203.0.113.71' ) );
		$lockout = \SentinelShield\Admin\View::take_result( 'lockout' );
		$this->assertSame( '203.0.113.71', $lockout['ip'] );
		$this->assertArrayHasKey( 'step', $lockout );

		reset_phpmailer_instance();
		$this->assertContains( 'success', self::types( $this->post( 'tool', array( 'tool' => 'send_unlock' ) ) ) );
		$this->assertStringContainsString( 'sentinel_unlock=', (string) tests_retrieve_phpmailer_instance()->get_sent()->body );

		$this->assertContains( 'success', self::types( $this->post( 'tool', array( 'tool' => 'flush_cache' ) ) ) );
		$this->assertContains( 'success', self::types( $this->post( 'tool', array( 'tool' => 'maintenance' ) ) ) );
		$r = $this->post( 'tool', array( 'tool' => 'cf_refresh', 'back' => 'ip' ) );
		$this->assertContains( 'error', self::types( $r ), 'offline: reported' );
		$this->assertStringContainsString( 'tab=ip_detection', $r[0] );
		$this->assertContains( 'error', self::types( $this->post( 'tool', array( 'tool' => 'nonsense' ) ) ) );
	}

	public function test_server_alerts_login_geo_and_feeds(): void {
		$c = Plugin::instance()->container();
		update_site_option( Settings::OPTION, array( 'firewall' => array( 'early_gate' => 'mu_plugin' ) ) );
		$c->get( Settings::class )->refresh();
		$this->assertContains( 'success', self::types( $this->post( 'server', array( 'op' => 'recheck' ) ) ) );
		$this->assertContains( 'success', self::types( $this->post( 'server', array( 'op' => 'rebuild' ) ) ) );
		$this->assertContains( 'success', self::types( $this->post( 'server', array( 'op' => 'cf_token', 'token' => 'tok' ) ) ) );
		$this->assertTrue( $c->get( CloudflareSync::class )->has_token() );
		$this->assertContains( 'error', self::types( $this->post( 'server', array( 'op' => 'cf_test' ) ) ), 'no account or list yet' );
		$this->assertContains( 'error', self::types( $this->post( 'server', array( 'op' => 'cf_sync' ) ) ), 'sync not switched on' );
		$this->assertContains( 'success', self::types( $this->post( 'server', array( 'op' => 'cf_token', 'token' => '' ) ) ) );
		$this->assertFalse( $c->get( CloudflareSync::class )->has_token() );
		$this->assertContains( 'error', self::types( $this->post( 'server', array( 'op' => 'nonsense' ) ) ) );

		$this->assertContains( 'info', self::types( $this->post( 'alerts', array( 'op' => 'test' ) ) ) );
		$this->assertContains( 'success', self::types( $this->post( 'alerts', array( 'op' => 'send' ) ) ), 'nothing to send' );
		$secret = AuditExporter::secret();
		$this->post( 'alerts', array( 'op' => 'new_secret' ) );
		$this->assertNotSame( $secret, AuditExporter::secret() );
		$this->assertContains( 'error', self::types( $this->post( 'alerts', array( 'op' => 'nonsense' ) ) ) );

		$c->get( LoginAttemptRepository::class )->record( (string) inet_pton( '198.51.100.88' ), 'someone', time() );
		$this->assertContains( 'success', self::types( $this->post( 'login_security', array( 'op' => 'clear' ) ) ) );
		$this->assertSame( 0, $c->get( LoginAttemptRepository::class )->count_ip( (string) inet_pton( '198.51.100.88' ), time() - 600 ) );
		$this->assertContains( 'error', self::types( $this->post( 'login_security', array( 'op' => 'nonsense' ) ) ) );

		$this->post( 'geo', array( 'op' => 'lookup', 'ip' => '203.0.113.9', 'user' => '' ) );
		$this->assertSame( '203.0.113.9', \SentinelShield\Admin\View::take_result( 'geo_lookup' )['ip'] );
		$this->assertContains( 'error', self::types( $this->post( 'geo', array( 'op' => 'update' ) ) ), 'offline: reported' );
		$this->assertContains( 'error', self::types( $this->post( 'geo', array( 'op' => 'nonsense' ) ) ) );

		$this->assertContains( 'error', self::types( $this->post( 'feeds_update', array( 'feed' => 'spamhaus_drop' ) ) ), 'not enabled' );
		update_site_option( Settings::OPTION, array( 'feeds' => array( 'lists' => array( 'spamhaus_drop' => true ) ) ) );
		$c->get( Settings::class )->refresh();
		$this->assertContains( 'error', self::types( $this->post( 'feeds_update', array( 'feed' => 'all' ) ) ), 'offline: reported' );
	}

	public function test_lockdown_and_scheduled_tasks(): void {
		$r = $this->post( 'lockdown', array( 'op' => 'scan' ) );
		$this->assertNotEmpty( array_intersect( array( 'success', 'warning' ), self::types( $r ) ) );
		$this->assertStringContainsString( '#ss-scan', $r[0] );
		$this->assertContains( 'error', self::types( $this->post( 'lockdown', array( 'op' => 'approve', 'id' => 'nothing' ) ) ) );
		$editor = (int) self::factory()->user->create( array( 'role' => 'editor' ) );
		$this->assertContains( 'error', self::types( $this->post( 'lockdown', array( 'op' => 'approve_admin', 'user_id' => $editor ) ) ), 'not an administrator' );
		$other = self::create_admin();
		$this->assertContains( 'success', self::types( $this->post( 'lockdown', array( 'op' => 'approve_admin', 'user_id' => $other ) ) ) );
		$this->assertTrue( Plugin::instance()->container()->get( AdminRegistry::class )->is_approved( get_userdata( $other ) ) );
		$this->assertContains( 'success', self::types( $this->post( 'lockdown', array( 'op' => 'revoke_admin', 'user_id' => $other ) ) ) );
		$this->assertContains( 'error', self::types( $this->post( 'lockdown', array( 'op' => 'revoke_admin', 'user_id' => $this->admin ) ) ), 'not your own' );
		$this->assertContains( 'error', self::types( $this->post( 'lockdown', array( 'op' => 'nonsense' ) ) ) );

		$args  = array( 'x' );
		$when  = time() + 3600;
		$event = array(
			'timestamp' => $when,
			'hook'      => 'sentinel_shield_actions_probe',
			'sig'       => md5( serialize( $args ) ), // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.serialize_serialize -- WP-Cron's own key.
		);
		wp_schedule_single_event( $when, 'sentinel_shield_actions_probe', $args );
		$this->assertContains( 'success', self::types( $this->post( 'cron_control', array( 'op' => 'reschedule', 'schedule' => 'hourly' ) + $event ) ) );
		$this->assertSame( 'hourly', wp_get_schedule( 'sentinel_shield_actions_probe', $args ) );
		$event['timestamp'] = (string) wp_next_scheduled( 'sentinel_shield_actions_probe', $args );
		$this->assertContains( 'success', self::types( $this->post( 'cron_control', array( 'op' => 'pause' ) + $event ) ) );
		$this->assertFalse( wp_next_scheduled( 'sentinel_shield_actions_probe', $args ), 'paused' );
		$key = (string) array_key_first( \SentinelShield\Cron\CronControl::paused() );
		$this->assertContains( 'success', self::types( $this->post( 'cron_control', array( 'op' => 'resume', 'key' => $key ) ) ) );
		$this->assertNotFalse( wp_next_scheduled( 'sentinel_shield_actions_probe', $args ), 'resumed' );
		$event['timestamp'] = (string) wp_next_scheduled( 'sentinel_shield_actions_probe', $args );
		$this->assertContains( 'success', self::types( $this->post( 'cron_control', array( 'op' => 'delete' ) + $event ) ) );
		$this->assertFalse( wp_next_scheduled( 'sentinel_shield_actions_probe', $args ) );
		$this->assertContains( 'error', self::types( $this->post( 'cron_control', array( 'op' => 'run' ) + $event ) ), 'already gone' );
		$this->assertContains( 'error', self::types( $this->post( 'cron_control', array( 'op' => 'forget', 'key' => 'none' ) ) ) );

		$this->post( 'lockdown', array( 'op' => 'logout_all' ) );
		$this->assertSame( array(), \WP_Session_Tokens::get_instance( $this->admin )->get_all(), 'every session ended' );
	}

	public function test_own_two_factor_settings(): void {
		$users = Plugin::instance()->container()->get( UserTwoFactor::class );
		$r     = $this->post( TwoFactorPage::ACTION, array( 'op' => 'backup_new' ) );
		$this->assertContains( 'error', self::types( $r ), 'needs a fresh confirmation first' );
		$this->assertSame( 0, $users->backup_remaining( $this->admin ) );

		$r = $this->post( TwoFactorPage::ACTION, array( 'op' => 'reauth', 'password' => 'right-pass' ) );
		$this->assertContains( 'success', self::types( $r ), wp_json_encode( $r ) );
		$this->assertContains( 'error', self::types( $this->post( TwoFactorPage::ACTION, array( 'op' => 'reauth', 'password' => 'wrong' ) ) ) );
		$this->assertNotSame( '', wp_get_session_token() );
		$this->assertTrue( $users->recently_confirmed( $this->admin, wp_get_session_token(), time() ), 'confirmed for this session' );

		$secret = $users->pending_secret( $this->admin );
		$this->assertContains( 'error', self::types( $this->post( TwoFactorPage::ACTION, array( 'op' => 'totp_enable', 'code' => '000000' ) ) ) );
		$this->assertContains( 'success', self::types( $this->post( TwoFactorPage::ACTION, array( 'op' => 'totp_enable', 'code' => Totp::code( $secret, intdiv( time(), 30 ) ) ) ) ) );
		$this->assertTrue( $users->has_totp( $this->admin ) );
		$this->assertSame( 10, $users->backup_remaining( $this->admin ), 'first backup codes created' );
		$this->post( TwoFactorPage::ACTION, array( 'op' => 'backup_new' ) );
		$this->assertSame( 10, $users->backup_remaining( $this->admin ) );
		$this->assertContains( 'success', self::types( $this->post( TwoFactorPage::ACTION, array( 'op' => 'email_on' ) ) ) );
		$this->assertTrue( $users->email_enabled( $this->admin ) );
		$this->assertContains( 'success', self::types( $this->post( TwoFactorPage::ACTION, array( 'op' => 'email_off' ) ) ) );
		$this->assertContains( 'success', self::types( $this->post( TwoFactorPage::ACTION, array( 'op' => 'forget_devices' ) ) ) );
		$this->assertContains( 'error', self::types( $this->post( TwoFactorPage::ACTION, array( 'op' => 'passkey_add', 'passkey' => '{}' ) ) ), 'no registration under way' );
		$this->assertContains( 'success', self::types( $this->post( TwoFactorPage::ACTION, array( 'op' => 'totp_remove' ) ) ) );
		$this->assertFalse( $users->has_totp( $this->admin ) );
	}
}
