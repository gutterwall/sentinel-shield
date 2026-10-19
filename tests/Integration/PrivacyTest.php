<?php
/**
 * Secrets never end up in logs, exports, pages or error messages.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Tests\Integration;

use SentinelShield\Admin\CronPage;
use SentinelShield\Admin\DashboardPage;
use SentinelShield\Admin\EventsPage;
use SentinelShield\Admin\LockdownPage;
use SentinelShield\Admin\RulesPage;
use SentinelShield\Admin\SettingsPage;
use SentinelShield\Admin\ToolsPage;
use SentinelShield\Admin\TwoFactorPage;
use SentinelShield\Audit\AuditExporter;
use SentinelShield\Firewall\CloudflareSync;
use SentinelShield\Plugin;
use SentinelShield\Repository\TokenRepository;
use SentinelShield\Settings;
use SentinelShield\SettingsSchema;
use SentinelShield\TwoFactor\Totp;
use SentinelShield\TwoFactor\TwoFactorLogin;
use SentinelShield\TwoFactor\UserTwoFactor;
use SentinelShield\Unlock\UnlockService;

/**
 * Review 5: passwords (right and wrong), authenticator secrets, backup codes,
 * emailed codes, unlock tokens, application passwords, the Cloudflare token
 * and credentials in the audit webhook address are planted, then everything
 * the plugin stores, sends to the audit endpoint and shows in wp-admin is
 * searched for them. Showing a secret to its owner at the moment it is
 * created (a new backup code list, the QR code while setting up an app) is
 * by design and not part of the search.
 */
final class PrivacyTest extends \WP_UnitTestCase {

	use AdminUsers;

	private const WRONG_PASSWORD = 'Wrong-Pass-Privacy-7731';
	private const RIGHT_PASSWORD = 'Right-Pass-Privacy-1189';
	private const CF_TOKEN       = 'cf-secret-token-55aa77';
	private const HOOK_TOKEN     = 'hooktoken9988xyz';
	private const HOOK_PASSWORD  = 'hookpass4411qq';

	/**
	 * Requests to outside services: [address, headers and body].
	 *
	 * @var list<array{0:string, 1:string}>
	 */
	private array $sent = array();

	public function tear_down(): void {
		remove_all_filters( 'pre_http_request' );
		foreach ( array( Settings::OPTION, CloudflareSync::TOKEN, CloudflareSync::STATE, AuditExporter::STATE ) as $option ) {
			delete_site_option( $option );
		}
		Plugin::instance()->container()->get( Settings::class )->refresh();
		reset_phpmailer_instance();
		wp_set_current_user( 0 );
		parent::tear_down();
	}

	public function test_no_secret_is_logged_exported_or_shown(): void {
		$c = Plugin::instance()->container();
		reset_phpmailer_instance();
		update_site_option(
			Settings::OPTION,
			array(
				'general'    => array( 'test_mode' => false ),
				'cloudflare' => array(
					'sync'       => true,
					'account_id' => str_repeat( 'a', 32 ),
					'list_id'    => str_repeat( 'b', 32 ),
				),
				'audit'      => array(
					'webhook_url' => 'https://audit-user:' . self::HOOK_PASSWORD . '@audit.example.org/ingest?token=' . self::HOOK_TOKEN,
					'scope'       => 'all',
				),
			)
		);
		$c->get( Settings::class )->refresh();
		add_filter(
			'pre_http_request',
			function ( $pre, $args, $url ) {
				$this->sent[] = array( (string) $url, wp_json_encode( $args['headers'] ?? array() ) . "\n" . (string) ( $args['body'] ?? '' ) );
				// Every outside service fails, echoing what it was given (as some do).
				return array(
					'headers'  => array(),
					'body'     => wp_json_encode( array( 'success' => false, 'errors' => array( array( 'message' => 'refused: ' . (string) $url ) ) ) ),
					'response' => array( 'code' => 401, 'message' => 'Unauthorized' ),
					'cookies'  => array(),
					'filename' => null,
				);
			},
			10,
			3
		);

		// Accounts, codes and passwords.
		$users  = $c->get( UserTwoFactor::class );
		$admin  = self::create_admin_user( array( 'user_pass' => self::RIGHT_PASSWORD, 'user_login' => 'privacy_admin' ) );
		$member = self::factory()->user->create_and_get( array( 'user_pass' => self::RIGHT_PASSWORD, 'user_login' => 'privacy_member' ) );
		$secret = $users->pending_secret( $member->ID );
		$users->enable_totp( $member->ID, Totp::code( $secret, intdiv( time(), 30 ) - 3 ), time() - 90 );
		$backup = $users->new_backup_codes( $member->ID );
		$this->assertTrue( $users->use_backup_code( $member->ID, $backup[9] ) );
		$app = \WP_Application_Passwords::create_new_application_password( $member->ID, array( 'name' => 'privacy' ) );
		$this->assertIsArray( $app );
		$secrets = array(
			'wrong password'     => self::WRONG_PASSWORD,
			'right password'     => self::RIGHT_PASSWORD,
			'TOTP secret'        => $secret,
			'application pass'   => $app[0],
			'Cloudflare token'   => self::CF_TOKEN,
			'webhook token'      => self::HOOK_TOKEN,
			'webhook password'   => self::HOOK_PASSWORD,
			'plugin key'         => \SentinelShield\Support\Secret::get(),
			'audit signing key'  => AuditExporter::secret(),
		);
		foreach ( $backup as $i => $code ) {
			$secrets[ "backup code $i" ] = $code;
		}

		// Things that log, count and report.
		$_SERVER['REMOTE_ADDR'] = '198.51.100.77';
		wp_authenticate( 'privacy_member', self::WRONG_PASSWORD );
		wp_authenticate( 'nobody_here', self::WRONG_PASSWORD );
		wp_authenticate_application_password( null, 'privacy_member', self::WRONG_PASSWORD );
		$login = $c->get( TwoFactorLogin::class );
		$token = $login->begin( $member );
		$login->attempt( $member, $token, '000000' );
		$login->attempt( $member, $token, $backup[9] ); // Already used.
		$users->set_email( $member->ID, true );
		$token2 = $login->begin( $member );
		$login->send_email_code( $member, $token2 );
		$mails = array_column( (array) tests_retrieve_phpmailer_instance()->mock_sent, 'body' );
		preg_match( '/\b(\d{4}) (\d{4})\b/', (string) end( $mails ), $m );
		$this->assertNotEmpty( $m[1] ?? '', 'an emailed code was sent' );
		$secrets['emailed code'] = $m[1] . $m[2];
		$login->attempt( $member, $token2, '11111111' );

		$link                    = $c->get( UnlockService::class )->send_link( $admin, '198.51.100.78', true );
		$secrets['unlock token'] = (string) wp_parse_args( (string) wp_parse_url( $link, PHP_URL_QUERY ) )['sentinel_unlock'];
		$c->get( TokenRepository::class )->consume( 'not-the-token' );

		$cf = $c->get( CloudflareSync::class );
		$cf->set_token( self::CF_TOKEN );
		$cf->test();
		$cf->sync( true );
		$c->get( AuditExporter::class )->run( 5 );
		$this->assertNotSame( '', (string) ( AuditExporter::state()['error'] ?? '' ), 'the audit export failed and says why' );
		$this->assertNotSame( '', (string) ( CloudflareSync::state()['error'] ?? '' ), 'the Cloudflare sync failed and says why' );

		// What is stored: every plugin table, option and user meta value.
		global $wpdb;
		$stored = array();
		foreach ( (array) $wpdb->get_col( $wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( $wpdb->base_prefix . 'sentinel' ) . '%' ) ) as $table ) {
			$stored[ "table $table" ] = wp_json_encode( $wpdb->get_results( $wpdb->prepare( 'SELECT * FROM %i', $table ), ARRAY_A ) );
		}
		$options = $wpdb->get_results( $wpdb->prepare( 'SELECT option_name, option_value FROM %i WHERE option_name LIKE %s', $wpdb->options, '%sentinel%' ), ARRAY_A );
		if ( is_multisite() ) {
			$options = array_merge( $options, $wpdb->get_results( $wpdb->prepare( 'SELECT meta_key AS option_name, meta_value AS option_value FROM %i WHERE meta_key LIKE %s', $wpdb->sitemeta, '%sentinel%' ), ARRAY_A ) );
		}
		foreach ( $options as $row ) {
			// A result shown once to its owner (new backup codes) lives five minutes; not a log.
			if ( ! str_contains( $row['option_name'], 'sentinel_shield_result_' ) ) {
				$stored[ 'option ' . $row['option_name'] ] = (string) $row['option_value'];
			}
		}
		foreach ( $wpdb->get_results( $wpdb->prepare( 'SELECT meta_key, meta_value FROM %i WHERE meta_key LIKE %s', $wpdb->usermeta, '%sentinel%' ), ARRAY_A ) as $row ) {
			$stored[ 'user meta ' . $row['meta_key'] ] = (string) $row['meta_value'];
		}
		// Each request goes to its own address (credentials in it are for that
		// service); its headers and body are what must not leak anything.
		// The Cloudflare token itself goes to Cloudflare, by design.
		$stored['audit export payloads']   = implode( "\n", array_column( array_filter( $this->sent, static fn( array $r ): bool => str_contains( $r[0], 'audit.example.org' ) ), 1 ) );
		$stored['other outgoing requests'] = implode( "\n", array_map( static fn( array $r ): string => $r[0] . "\n" . $r[1], array_filter( $this->sent, static fn( array $r ): bool => ! str_contains( $r[0], 'api.cloudflare.com' ) && ! str_contains( $r[0], 'audit.example.org' ) ) ) );

		// What administrators see: every admin screen and settings tab.
		wp_set_current_user( $admin->ID );
		$pages = array(
			'dashboard' => array( new DashboardPage( $c ), array() ),
			'rules'     => array( new RulesPage( $c ), array() ),
			'events'    => array( new EventsPage( $c ), array() ),
			'lockdown'  => array( new LockdownPage( $c ), array() ),
			'cron'      => array( new CronPage( $c ), array() ),
			'tools'     => array( new ToolsPage( $c ), array() ),
			'2fa'       => array( new TwoFactorPage( $c ), array() ),
		);
		foreach ( array_keys( SettingsSchema::tabs() ) as $tab ) {
			$pages[ "settings $tab" ] = array( new SettingsPage( $c ), array( 'tab' => $tab ) );
		}
		set_current_screen( 'dashboard' );
		foreach ( $pages as $name => [ $page, $get ] ) {
			$_GET = $get;
			ob_start();
			try {
				$page->render();
			} finally {
				$_GET = array();
			}
			$html                       = (string) ob_get_clean();
			$stored[ "admin page $name" ] = $html;
			$this->assertGreaterThan( 200, strlen( $html ), "$name rendered" );
		}

		// The webhook address is configuration: stored with the settings and
		// shown in the settings form for administrators to edit.
		$by_design = array(
			'option sentinel_shield_settings' => array( 'webhook token', 'webhook password' ),
			// The signing secret is shown there too, for the receiver's configuration.
			'admin page settings alerts'      => array( 'webhook token', 'webhook password', 'audit signing key' ),
			// Each key in its own store.
			'option sentinel_shield_secret'       => array( 'plugin key' ),
			'option sentinel_shield_audit_secret' => array( 'audit signing key' ),
		);
		foreach ( $stored as $where => $text ) {
			foreach ( $secrets as $what => $secret_value ) {
				if ( in_array( $what, $by_design[ $where ] ?? array(), true ) ) {
					continue;
				}
				$this->assertStringNotContainsString( (string) $secret_value, $text, "the $what appears in $where" );
				if ( strlen( (string) $secret_value ) >= 8 ) {
					$this->assertStringNotContainsString( rawurlencode( (string) $secret_value ), $text, "the $what appears (URL-encoded) in $where" );
				}
			}
		}
		$this->assertGreaterThan( 20, count( $stored ) );
	}
}
