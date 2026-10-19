<?php
/**
 * WP-CLI commands, run in-process: the recovery path when wp-admin is out of
 * reach.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Tests\Integration;

use SentinelShield\CLI\Command;
use SentinelShield\Firewall\CloudflareSync;
use SentinelShield\Firewall\EarlyGate;
use SentinelShield\Firewall\RuleCache;
use SentinelShield\Net\Cidr;
use SentinelShield\Plugin;
use SentinelShield\Repository\BlockRepository;
use SentinelShield\Repository\LoginAttemptRepository;
use SentinelShield\Repository\TokenRepository;
use SentinelShield\Settings;
use SentinelShield\Support\DataDir;
use SentinelShield\Tests\Fakes\CliError;
use SentinelShield\Tests\Fakes\CliHalt;
use SentinelShield\TwoFactor\UserTwoFactor;

require_once dirname( __DIR__ ) . '/Fakes/WpCli.php';

/**
 * Review 5 (recovery drills): what an administrator locked out of wp-admin
 * does from the command line works, step by step: unblock their address, turn
 * protection to test mode, roll the settings back from an export, rotate or
 * drop the Cloudflare token, reset someone's two-factor, get an unlock link;
 * and every other command at least runs and reports.
 */
final class CliCommandTest extends \WP_UnitTestCase {

	use AdminUsers;

	private Command $cli;

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
		$this->data = get_temp_dir() . 'ss-cli-' . wp_generate_password( 6, false );
		add_filter( 'sentinel_shield_data_dir', array( $this, 'private_dir' ) );
		$_SERVER['DOCUMENT_ROOT'] = ABSPATH;
		add_filter( 'pre_http_request', array( self::class, 'offline' ) );
		// Enforcing (new installations start in test mode).
		update_site_option( Settings::OPTION, array( 'general' => array( 'test_mode' => false ) ) );
		$c->get( Settings::class )->refresh();
		$this->cli = new Command( $c );
	}

	public function tear_down(): void {
		remove_filter( 'pre_http_request', array( self::class, 'offline' ) );
		remove_filter( 'sentinel_shield_data_dir', array( $this, 'private_dir' ) );
		exec( 'rm -rf ' . escapeshellarg( $this->data ) );
		foreach ( array( Settings::OPTION, CloudflareSync::TOKEN, CloudflareSync::STATE, DataDir::OPTION, DataDir::ROOT, EarlyGate::STATE ) as $option ) {
			delete_site_option( $option );
		}
		unset( $_SERVER['DOCUMENT_ROOT'] );
		Plugin::instance()->container()->get( Settings::class )->refresh();
		parent::tear_down();
	}

	public static function offline(): \WP_Error {
		return new \WP_Error( 'http_request_failed', 'No network in tests.' );
	}

	/**
	 * Runs a command; returns what it printed, and how it ended.
	 *
	 * @param string               $method Command method.
	 * @param list<string>         $args   Positional arguments.
	 * @param array<string, mixed> $assoc  Named arguments.
	 * @return array{out:string, items:list<array<string, mixed>>, error:?string, halt:?int}
	 */
	private function wp( string $method, array $args = array(), array $assoc = array() ): array {
		\WP_CLI::$out = array();
		$error        = null;
		$halt         = null;
		ob_start();
		try {
			$this->cli->$method( $args, $assoc );
		} catch ( CliError $e ) {
			$error = $e->getMessage();
		} catch ( CliHalt $e ) {
			$halt = $e->getCode();
		} finally {
			$echo = (string) ob_get_clean();
		}
		$items = array();
		$text  = $echo;
		foreach ( \WP_CLI::$out as [ $type, $message ] ) {
			if ( 'items' === $type ) {
				$items = array_merge( $items, (array) json_decode( $message, true ) );
			} else {
				$text .= "$type: $message\n";
			}
		}
		return array(
			'out'   => $text,
			'items' => $items,
			'error' => $error,
			'halt'  => $halt,
		);
	}

	public function test_locked_out_administrator_recovers_from_the_command_line(): void {
		$c = Plugin::instance()->container();
		// Locked out of their own site.
		$this->assertNull( $this->wp( 'lockout', array( '198.51.100.40' ), array( 'reason' => 'drill' ) )['error'] );
		$this->assertNotNull( $c->get( BlockRepository::class )->find_exact( 'block', Cidr::parse( '198.51.100.40' ) ) );
		$check = $this->wp( 'check', array( '198.51.100.40' ), array( 'uri' => '/wp-admin/' ) );
		$this->assertStringContainsString( 'block', strtolower( $check['out'] ) );

		// 1. Unblock the address.
		$this->assertStringContainsString( 'Removed 1 block rule', $this->wp( 'unblock', array( '198.51.100.40' ) )['out'] );
		$this->assertNull( $c->get( BlockRepository::class )->find_exact( 'block', Cidr::parse( '198.51.100.40' ) ) );

		// 2. Or switch enforcement to test mode for a while.
		$this->assertNull( $this->wp( 'test_mode', array( 'on' ), array( 'hours' => '2' ) )['error'] );
		$this->assertTrue( $c->get( Settings::class )->global_test_mode() );
		$this->wp( 'test_mode', array( 'off' ) );
		$this->assertFalse( $c->get( Settings::class )->global_test_mode() );

		// 3. Roll the settings back to an export.
		$this->wp( 'settings_set', array( 'login.max_failures', '5' ) );
		$file = get_temp_dir() . 'ss-settings-' . wp_generate_password( 6, false ) . '.json';
		$this->assertStringContainsString( 'Written to', $this->wp( 'settings_export', array( $file ) )['out'] );
		$this->assertStringContainsString( '"max_failures": 5', $this->wp( 'settings_export' )['out'] );
		$this->wp( 'settings_set', array( 'login.max_failures', '1' ) );
		$this->assertSame( 1, $c->get( Settings::class )->get( 'login.max_failures' ) );
		$import = $this->wp( 'settings_import', array( $file ) );
		wp_delete_file( $file );
		$this->assertNull( $import['error'], (string) $import['out'] );
		$this->assertSame( 5, $c->get( Settings::class )->get( 'login.max_failures' ), 'rolled back' );
		$this->assertNotNull( $this->wp( 'settings_import', array( '/no/such/file.json' ) )['error'] );

		// 4. An unlock link for an administrator (expired ones do not work).
		$admin = self::create_admin_user( array( 'user_email' => 'drill@example.org' ) );
		$link  = $this->wp( 'unlock_link', array( (string) $admin->user_login ), array( 'ip' => '198.51.100.41' ) );
		$this->assertStringContainsString( 'sentinel_unlock=', $link['out'] );
		$this->assertNotNull( $this->wp( 'unlock_link', array( 'nobody-here' ) )['error'] );

		// 5. Reset a user's two-factor (a lost phone).
		$users = $c->get( UserTwoFactor::class );
		$users->new_backup_codes( $admin->ID );
		$this->assertSame( 10, $users->backup_remaining( $admin->ID ) );
		$this->assertNull( $this->wp( 'two_factor', array( $admin->user_login ), array( 'reset' => true ) )['error'] );
		$this->assertSame( 0, $users->backup_remaining( $admin->ID ) );
		$this->assertNotEmpty( $this->wp( 'two_factor' )['items'], 'overview of all accounts' );

		// 6. Rotate or drop the Cloudflare credentials (dropping empties the list first).
		$cf = $c->get( CloudflareSync::class );
		$cf->set_token( 'old-token' );
		$cf->set_token( 'new-token' );
		$this->assertTrue( $cf->has_token() );
		$this->assertNotNull( $this->wp( 'cloudflare_sync' )['error'], 'sync not configured: said so' );
		$this->assertTrue( $cf->set_token( '' ) );
		$this->assertFalse( $cf->has_token() );
	}

	public function test_rules_and_reports(): void {
		$this->assertNull( $this->wp( 'block', array( '203.0.113.0/24' ), array( 'minutes' => '30', 'reason' => 'cli' ) )['error'] );
		$this->assertNull( $this->wp( 'allow', array( '203.0.113.7' ) )['error'] );
		$this->assertNotNull( $this->wp( 'block', array( 'nonsense' ) )['error'] );
		$list = $this->wp( 'list_', array(), array( 'type' => 'block' ) );
		$this->assertContains( '203.0.113.0/24', array_column( $list['items'], 'label' ) );
		$id = (int) $list['items'][0]['id'];
		$this->assertStringContainsStringIgnoringCase( 'still covered', $this->wp( 'unblock', array( '203.0.113.9' ) )['out'] );
		$this->assertNull( $this->wp( 'remove', array( (string) $id ) )['error'] );
		$this->assertNotNull( $this->wp( 'remove', array( '999999' ) )['error'] );
		$this->assertNotNull( $this->wp( 'unblock', array( 'nonsense' ) )['error'] );

		$this->assertNull( $this->wp( 'resolve_ip', array(), array( 'remote-addr' => '10.0.0.1', 'headers' => 'X-Forwarded-For: 203.0.113.50', 'mode' => 'custom' ) )['error'] );
		$this->assertNull( $this->wp( 'status' )['error'] );
		$this->assertNull( $this->wp( 'settings_get', array( 'login.max_failures' ) )['error'] );
		$this->assertNotNull( $this->wp( 'settings_get', array( 'no.such' ) )['error'] );
		$this->assertNotNull( $this->wp( 'settings_set', array( 'no.such', '1' ) )['error'] );
		$this->assertNotEmpty( $this->wp( 'settings_keys' )['items'] );
		$this->assertNull( $this->wp( 'flush_cache' )['error'] );
		$this->assertNotNull( $this->wp( 'cloudflare_update' )['error'], 'offline: said so' );

		Plugin::instance()->container()->get( LoginAttemptRepository::class )->record( (string) inet_pton( '198.51.100.60' ), 'someone', time() );
		$this->assertNotEmpty( $this->wp( 'login_attempts' )['items'] );
		$this->wp( 'login_attempts', array(), array( 'clear' => true ) );
		$this->assertSame( array(), $this->wp( 'login_attempts' )['items'] );

		$this->assertNull( $this->wp( 'cron' )['error'] );
		$this->assertNull( $this->wp( 'feeds' )['error'] );
		$this->assertNotNull( $this->wp( 'feeds_update' )['error'], 'no list enabled' );
		$this->assertNull( $this->wp( 'geo', array( '203.0.113.9' ) )['error'] );
		$this->assertNotNull( $this->wp( 'geo_update' )['error'], 'offline: said so' );
		$this->assertNull( $this->wp( 'events', array(), array( 'limit' => '5' ) )['error'] );
		$this->assertNull( $this->wp( 'prune' )['error'] );
		$lines = array_filter( explode( "\n", $this->wp( 'audit_export', array(), array( 'days' => '1' ) )['out'] ) );
		$this->assertNotEmpty( $lines, 'the rule changes above were logged' );
		foreach ( $lines as $line ) {
			$event = json_decode( substr( $line, strlen( 'line: ' ) ), true );
			$this->assertIsArray( $event );
			$this->assertArrayHasKey( 'hash', $event, 'chained like the webhook deliveries' );
		}
		$this->assertNull( $this->wp( 'audit_test' )['error'] );
		$this->assertNull( $this->wp( 'admins' )['error'] );
		$admin = self::create_admin_user();
		$this->assertNull( $this->wp( 'approve_admin', array( $admin->user_login ) )['error'] );
		$this->assertNull( $this->wp( 'revoke_admin', array( $admin->user_login ) )['error'] );
		$this->assertNotNull( $this->wp( 'approve_admin', array( 'nobody-here' ) )['error'] );
	}

	public function test_early_firewall_server_files_and_scans(): void {
		update_site_option( Settings::OPTION, array( 'general' => array( 'test_mode' => false ), 'firewall' => array( 'early_gate' => 'mu_plugin', 'server_files' => true ) ) );
		Plugin::instance()->container()->get( Settings::class )->refresh();
		Plugin::instance()->container()->get( BlockRepository::class )->add( 'block', Cidr::parse( '192.0.2.0/24' ), 'cli', 'manual' );
		Plugin::instance()->container()->get( RuleCache::class )->flush();
		$this->assertStringContainsString( 'Snapshot rebuilt', $this->wp( 'early_gate', array( 'rebuild' ) )['out'] );
		$this->assertNull( $this->wp( 'early_gate' )['error'] );
		$this->assertStringContainsString( 'deny 192.0.2.0/24;', $this->wp( 'server_export', array( 'nginx' ) )['out'] );
		$this->assertStringContainsString( 'Require not ip 192.0.2.0/24', $this->wp( 'server_export', array( 'apache' ) )['out'] );
		$this->assertNotNull( $this->wp( 'server_export', array( 'iis' ) )['error'] );
		$health = $this->wp( 'health' );
		$this->assertNotSame( '', $health['out'] . wp_json_encode( $health['items'] ) );
		$scan = $this->wp( 'scan' );
		$this->assertTrue( null === $scan['error'], (string) $scan['error'] );
		$verify = $this->wp( 'verify' );
		$this->assertTrue( null === $verify['error'] || str_contains( (string) $verify['error'], 'WordPress.org' ), (string) $verify['error'] );
	}
}
