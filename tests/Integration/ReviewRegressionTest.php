<?php
/**
 * Regression tests for the October 2026 code review findings.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Tests\Integration;

use SentinelShield\Admin\Actions;
use SentinelShield\Geo\CountryDatabase;
use SentinelShield\Geo\GeoResolver;
use SentinelShield\Login\BruteForceGuard;
use SentinelShield\Net\CloudflareRanges;
use SentinelShield\Plugin;
use SentinelShield\Repository\EventRepository;
use SentinelShield\Repository\LoginAttemptRepository;
use SentinelShield\Repository\TokenRepository;
use SentinelShield\Settings;
use SentinelShield\Support\Mutex;
use SentinelShield\TwoFactor\SecretBox;
use SentinelShield\TwoFactor\TwoFactorLogin;
use SentinelShield\TwoFactor\UserTwoFactor;
use SentinelShield\Unlock\UnlockService;

final class ReviewRegressionTest extends \WP_UnitTestCase {

	use AdminUsers;

	public function set_up(): void {
		parent::set_up();
		global $wpdb;
		$c = Plugin::instance()->container();
		$wpdb->query( $wpdb->prepare( 'DELETE FROM %i', $c->get( EventRepository::class )->table() ) );
		$wpdb->query( $wpdb->prepare( 'DELETE FROM %i', $c->get( TokenRepository::class )->table() ) );
		$c->get( LoginAttemptRepository::class )->clear_all();
		reset_phpmailer_instance();
	}

	public function tear_down(): void {
		unset( $_GET['sentinel_unlock'], $_POST['sentinel_unlock_confirm'] );
		delete_site_option( Settings::OPTION );
		Plugin::instance()->container()->get( Settings::class )->refresh();
		parent::tear_down();
	}

	/**
	 * Saves settings and returns the refreshed Settings service.
	 *
	 * @param array<string, mixed> $values Settings.
	 */
	private static function settings( array $values ): Settings {
		update_site_option( Settings::OPTION, $values );
		$settings = Plugin::instance()->container()->get( Settings::class );
		$settings->refresh();
		return $settings;
	}

	/**
	 * A second database connection, to hold locks like another PHP worker.
	 */
	private static function other_connection(): \wpdb {
		$db = new \wpdb( DB_USER, DB_PASSWORD, DB_NAME, DB_HOST );
		$db->suppress_errors( true );
		return $db;
	}

	/**
	 * The database lock name Mutex uses for a name.
	 *
	 * @param string $name Lock name.
	 */
	private static function lock_name( string $name ): string {
		$method = new \ReflectionMethod( Mutex::class, 'db_name' );
		$method->setAccessible( true );
		return (string) $method->invoke( null, $name );
	}

	/**
	 * @return list<string>
	 */
	private static function event_types(): array {
		return array_column( Plugin::instance()->container()->get( EventRepository::class )->query( array() )[0], 'event' );
	}

	/**
	 * Finding 3: a server variable that is really a request header (HTTP_*) only
	 * counts when a trusted proxy named the visitor.
	 */
	public function test_header_country_variable_needs_a_trusted_proxy(): void {
		$settings = self::settings( array( 'geo' => array( 'server_var' => 'HTTP_CF_IPCOUNTRY' ) ) );
		$db       = Plugin::instance()->container()->get( CountryDatabase::class );
		$server   = array( 'HTTP_CF_IPCOUNTRY' => 'FR' );
		$resolve  = static fn( array $details, string $ip = '203.0.113.9' ): string => ( new GeoResolver( $settings, $db, $server, static fn(): array => $details ) )->server_variable( $ip );

		$this->assertSame( '', $resolve( array( 'mode' => 'none', 'remote_trusted' => false, 'fallback' => false, 'ip' => '203.0.113.9' ) ), 'No proxy: anyone can send the header.' );
		$this->assertSame( '', $resolve( array( 'mode' => 'custom', 'remote_trusted' => false, 'fallback' => false, 'ip' => '203.0.113.9' ) ), 'Sent directly, not through the proxy.' );
		$this->assertSame( '', $resolve( array( 'mode' => 'custom', 'remote_trusted' => true, 'fallback' => true, 'ip' => '10.0.0.5' ), '10.0.0.5' ), 'Through the proxy, but the visitor is unknown.' );
		$this->assertSame( '', $resolve( array( 'mode' => 'custom', 'remote_trusted' => true, 'fallback' => false, 'ip' => '198.51.100.1' ) ), 'Another IP than this request\'s visitor.' );
		$this->assertSame( 'FR', $resolve( array( 'mode' => 'custom', 'remote_trusted' => true, 'fallback' => false, 'ip' => '203.0.113.9' ) ) );

		$settings = self::settings( array( 'geo' => array( 'server_var' => 'GEOIP_COUNTRY_CODE' ) ) );
		$server   = array( 'GEOIP_COUNTRY_CODE' => 'GB' );
		$resolve  = static fn( array $details, string $ip = '203.0.113.9' ): string => ( new GeoResolver( $settings, $db, $server, static fn(): array => $details ) )->server_variable( $ip );
		$this->assertSame( 'GB', $resolve( array( 'mode' => 'none', 'remote_trusted' => false, 'fallback' => false, 'ip' => '203.0.113.9' ) ), 'Set by the web server: always used.' );
	}

	/**
	 * Finding 4: unused links die when the account is deleted or demoted.
	 */
	public function test_unlock_links_are_revoked_with_the_right_to_unlock(): void {
		$tokens = Plugin::instance()->container()->get( TokenRepository::class );
		$admin  = self::create_admin_user();
		$other  = self::create_admin_user();
		$token  = $tokens->create( $admin->ID, '203.0.113.9', 600 );
		$kept   = $tokens->create( $other->ID, '203.0.113.9', 600 );

		self::demote( $admin->ID );
		$this->assertNull( $tokens->peek( $token ), 'Demoted: link invalidated.' );
		$this->assertNotNull( $tokens->peek( $kept ), 'Other accounts keep theirs.' );
		$this->assertContains( 'unlock_revoked', self::event_types() );

		require_once ABSPATH . 'wp-admin/includes/user.php';
		if ( is_multisite() ) {
			// A network deletes super admins only after revoking them (which already invalidates links).
			require_once ABSPATH . 'wp-admin/includes/ms.php';
			revoke_super_admin( $other->ID );
			wpmu_delete_user( $other->ID );
		} else {
			wp_delete_user( $other->ID );
		}
		$this->assertNull( $tokens->peek( $kept ), 'Deleted: link invalidated.' );
	}

	/**
	 * Finding 4: a link is checked against its account when used, even when the
	 * right to unlock went away without a role change (e.g. a capability edit).
	 */
	public function test_unlock_link_is_refused_when_its_account_can_no_longer_unlock(): void {
		$c      = Plugin::instance()->container();
		$tokens = $c->get( TokenRepository::class );
		$admin  = self::create_admin_user();
		$token  = $tokens->create( $admin->ID, '203.0.113.9', 600 );
		$filter = static function ( array $caps, array $cap, array $args ) use ( $admin ): array {
			if ( isset( $args[1] ) && (int) $args[1] === $admin->ID ) {
				unset( $caps['manage_options'] );
			}
			return $caps;
		};
		add_filter( 'user_has_cap', $filter, 10, 3 );
		// On multisite the right to unlock is super admin status; drop it without any hook.
		$not_super = static fn( $admins ): array => array_values( array_diff( (array) $admins, array( $admin->user_login ) ) );
		add_filter( 'site_option_site_admins', $not_super );

		$_GET['sentinel_unlock']          = $token;
		$_POST['sentinel_unlock_confirm'] = '1';
		try {
			$c->get( UnlockService::class )->on_init();
			$this->fail( 'The link should be refused.' );
		} catch ( \WPDieException $e ) {
			$this->assertStringContainsString( 'invalid', $e->getMessage() );
		} finally {
			remove_filter( 'user_has_cap', $filter, 10 );
			remove_filter( 'site_option_site_admins', $not_super );
		}
		$this->assertNull( $tokens->peek( $token ) );
		$this->assertContains( 'unlock_refused', self::event_types() );
		$this->assertNotContains( 'unlock', self::event_types(), 'Nothing was unblocked.' );
	}

	/**
	 * Finding 5: per-account cooldown, hourly and open-link caps, and a site cap,
	 * all answered with the generic message.
	 */
	public function test_unlock_emails_are_limited_per_account_and_site(): void {
		$c       = Plugin::instance()->container();
		$service = $c->get( UnlockService::class );
		$tokens  = $c->get( TokenRepository::class );
		$method  = new \ReflectionMethod( UnlockService::class, 'request_locked' );
		$method->setAccessible( true );
		$mail    = new \ReflectionMethod( UnlockService::class, 'mail_link' );
		$mail->setAccessible( true );
		// What handle_request() does: decide under the lock, send after it.
		$request = static function ( string $ip, string $email ) use ( $method, $mail, $service ): string {
			$out = (array) $method->invoke( $service, $ip, $email, 'generic' );
			if ( isset( $out['user'], $out['url'] ) ) {
				$mail->invoke( $service, $out['user'], $ip, $out['url'] );
			}
			return (string) $out['message'];
		};
		$admin   = self::create_admin_user();
		reset_phpmailer_instance();

		$this->assertSame( 'generic', $request( '198.51.100.1', $admin->user_email ) );
		$this->assertCount( 1, tests_retrieve_phpmailer_instance()->mock_sent );
		// A second IP (as in a distributed attack) inside the cooldown: no email, same answer.
		$this->assertSame( 'generic', $request( '198.51.100.2', $admin->user_email ) );
		$this->assertCount( 1, tests_retrieve_phpmailer_instance()->mock_sent );
		$this->assertContains( 'unlock_limited', self::event_types() );
		$this->assertSame( 'generic', $request( '198.51.100.3', 'nobody@example.org' ), 'Unknown address: same answer.' );

		// Past the cooldown but with too many open links.
		global $wpdb;
		$wpdb->query( $wpdb->prepare( 'UPDATE %i SET created_at = %s', $tokens->table(), gmdate( 'Y-m-d H:i:s', time() - 400 ) ) );
		$tokens->create( $admin->ID, '198.51.100.4', 600 );
		$wpdb->query( $wpdb->prepare( 'UPDATE %i SET created_at = %s', $tokens->table(), gmdate( 'Y-m-d H:i:s', time() - 400 ) ) );
		$this->assertSame( UnlockService::ACCOUNT_OPEN, $tokens->count_outstanding( $admin->ID ) );
		$request( '198.51.100.5', $admin->user_email );
		$this->assertCount( 1, tests_retrieve_phpmailer_instance()->mock_sent );

		// Site-wide cap: other administrators' links count too.
		$wpdb->query( $wpdb->prepare( 'DELETE FROM %i', $tokens->table() ) );
		for ( $i = 0; $i < UnlockService::SITE_PER_HOUR; $i++ ) {
			$tokens->create( 999000 + $i, '198.51.100.6', 600 );
		}
		$request( '198.51.100.7', $admin->user_email );
		$this->assertCount( 1, tests_retrieve_phpmailer_instance()->mock_sent );
	}

	/**
	 * Finding 6a: an account that must use two-factor authentication but has no
	 * method is refused, never let in with the password alone, and the refusal
	 * is not counted as a password guess.
	 */
	public function test_required_two_factor_without_any_method_refuses_the_login(): void {
		$c        = Plugin::instance()->container();
		$settings = self::settings( array( 'twofa' => array( 'required' => 'all', 'email' => false ) ) );
		$users    = $c->get( UserTwoFactor::class );
		$step     = new TwoFactorLogin( $settings, $users, $c->get( SecretBox::class ), $c->get( EventRepository::class ), static fn(): string => '198.51.100.20' );
		$user     = self::factory()->user->create_and_get( array( 'user_pass' => 'pw' ) );

		$this->assertSame( array(), $step->methods( $user ) );
		$this->assertTrue( $step->needs_second_step( $user ) );
		$this->assertTrue( $step->locked_out( $user ) );
		$result = $step->authenticate( $user );
		$this->assertWPError( $result );
		$this->assertSame( TwoFactorLogin::ERROR_SETUP, $result->get_error_code() );
		$this->assertContains( 'twofa_no_method', self::event_types() );

		$guard = $c->get( BruteForceGuard::class );
		$guard->failed( $user->user_login, $result );
		$this->assertSame( 0, $c->get( LoginAttemptRepository::class )->count_since( 0 ), 'Not a password guess.' );

		$settings = self::settings( array( 'twofa' => array( 'required' => 'all', 'email' => true ) ) );
		$this->assertFalse( $step->locked_out( $user ), 'With email codes allowed it gets a code instead.' );
	}

	/**
	 * Finding 6a: an administrator cannot save settings that would make their
	 * own next login impossible.
	 */
	public function test_cannot_switch_off_email_codes_that_your_own_login_needs(): void {
		$admin = self::create_admin_user();
		wp_set_current_user( $admin->ID );
		$actions = new Actions( Plugin::instance()->container() );
		$method  = new \ReflectionMethod( Actions::class, 'keep_own_twofa_login' );
		$method->setAccessible( true );
		$keep = static fn( array $twofa ): array => (array) $method->invoke( $actions, array( 'twofa' => $twofa ) )['twofa'];

		$this->assertTrue( $keep( array( 'required' => 'privileged', 'email' => false ) )['email'] );
		$this->assertTrue( $keep( array( 'required' => 'all', 'email' => false ) )['email'] );
		$this->assertFalse( $keep( array( 'required' => 'none', 'email' => false ) )['email'], 'Not required: allowed.' );

		$editor = self::factory()->user->create_and_get( array( 'role' => 'editor' ) );
		wp_set_current_user( $editor->ID );
		$this->assertFalse( $keep( array( 'required' => 'privileged', 'email' => false ) )['email'], 'Not covered by the requirement.' );
		wp_set_current_user( 0 );
	}

	/**
	 * Finding 6b: the lock really excludes other workers, and a busy lock is
	 * reported instead of running the work unprotected.
	 */
	public function test_mutex_excludes_other_connections(): void {
		$other = self::other_connection();
		$this->assertSame( '1', (string) $other->get_var( $other->prepare( 'SELECT GET_LOCK(%s, 0)', self::lock_name( 'twofa_42' ) ) ) );
		$this->assertFalse( Mutex::acquire( 'twofa_42', 0 ) );
		$this->assertSame( 'busy', Mutex::run( 'twofa_42', 0, static fn(): string => 'ran', 'busy' ) );
		$other->query( $other->prepare( 'SELECT RELEASE_LOCK(%s)', self::lock_name( 'twofa_42' ) ) );

		$this->assertSame( 'ran', Mutex::run( 'twofa_42', 0, static fn(): string => 'ran', 'busy' ) );
		$this->assertTrue( Mutex::acquire( 'twofa_42', 0 ) );
		$this->assertTrue( Mutex::acquire( 'twofa_42', 0 ), 're-entrant' );
		Mutex::release( 'twofa_42' );
		$this->assertTrue( Mutex::holds( 'twofa_42' ) );
		Mutex::release( 'twofa_42' );
		$this->assertFalse( Mutex::holds( 'twofa_42' ) );
		$this->assertSame( '1', (string) $other->get_var( $other->prepare( 'SELECT GET_LOCK(%s, 0)', self::lock_name( 'twofa_42' ) ) ), 'Released for others.' );
		$other->close();
	}

	/**
	 * Review 2 finding 6: when named locks give no answer, an atomic lock row is
	 * used; when that fails too, the lock is not reported as taken.
	 */
	public function test_mutex_falls_back_to_a_lock_row_and_fails_closed(): void {
		global $wpdb;
		$no_named = static fn( string $q ): string => str_contains( $q, 'GET_LOCK' ) ? 'SELECT NULL' : $q;
		add_filter( 'query', $no_named );
		$row   = '_' . self::lock_name( 'fallback_test' );
		$table = $wpdb->base_prefix . 'options';
		try {
			$this->assertTrue( Mutex::acquire( 'fallback_test', 0 ) );
			$this->assertSame( 'row', Mutex::status()['mode'] );
			$this->assertNotNull( $wpdb->get_var( $wpdb->prepare( 'SELECT option_value FROM %i WHERE option_name = %s', $table, $row ) ) );
			Mutex::release( 'fallback_test' );
			$this->assertNull( $wpdb->get_var( $wpdb->prepare( 'SELECT option_value FROM %i WHERE option_name = %s', $table, $row ) ), 'released' );

			// Held by another worker: busy. Its lease ran out: taken over.
			$wpdb->insert( $table, array( 'option_name' => $row, 'option_value' => (string) ( time() + 60 ), 'autoload' => 'no' ) );
			$this->assertFalse( Mutex::acquire( 'fallback_test', 0 ) );
			$wpdb->update( $table, array( 'option_value' => (string) ( time() - 5 ) ), array( 'option_name' => $row ) );
			$this->assertTrue( Mutex::acquire( 'fallback_test', 0 ) );
			Mutex::release( 'fallback_test' );

			// No lock at all: refused, and reported for the health screen.
			$broken = static fn( string $q ): string => str_contains( $q, 'INSERT IGNORE' ) ? 'INSERT INTO no_such_table_ss VALUES (1)' : $q;
			add_filter( 'query', $broken );
			$this->assertFalse( Mutex::acquire( 'fallback_test_2', 0 ) );
			$this->assertSame( 'failed', Mutex::status()['mode'] );
			remove_filter( 'query', $broken );
		} finally {
			remove_filter( 'query', $no_named );
		}
	}

	/**
	 * Review 3 finding 5: a worker whose lease ran out cannot release the lock
	 * row another worker has taken over since.
	 */
	public function test_fallback_lock_release_checks_the_owner(): void {
		global $wpdb;
		$no_named = static fn( string $q ): string => str_contains( $q, 'GET_LOCK' ) ? 'SELECT NULL' : $q;
		add_filter( 'query', $no_named );
		$row   = '_' . self::lock_name( 'owner_test' );
		$table = $wpdb->base_prefix . 'options';
		try {
			$this->assertTrue( Mutex::acquire( 'owner_test', 0 ) );
			$this->assertTrue( Mutex::renew( 'owner_test' ), 'the holder can extend its lease' );
			// Our lease ran out and another worker took the row over.
			$wpdb->update( $table, array( 'option_value' => ( time() + 60 ) . '|other-worker' ), array( 'option_name' => $row ) );
			$this->assertFalse( Mutex::renew( 'owner_test' ), 'a lost lease cannot be renewed' );
			Mutex::release( 'owner_test' );
			$this->assertSame( ( time() + 60 ) . '|other-worker', $wpdb->get_var( $wpdb->prepare( 'SELECT option_value FROM %i WHERE option_name = %s', $table, $row ) ), 'the other worker\'s lock survives' );
			$wpdb->delete( $table, array( 'option_name' => $row ) );
		} finally {
			remove_filter( 'query', $no_named );
		}
	}

	/**
	 * Review 3 finding 6: confirming identity on the two-factor page has an
	 * attempt limit and, with an app set up, needs its code too.
	 */
	public function test_identity_confirmation_is_limited_and_needs_the_second_factor(): void {
		$user = self::factory()->user->create_and_get( array( 'user_pass' => 'right-pass' ) );
		wp_set_current_user( $user->ID );
		$page    = new \SentinelShield\Admin\TwoFactorPage( Plugin::instance()->container() );
		$confirm = new \ReflectionMethod( $page, 'confirm_identity' );
		$confirm->setAccessible( true );
		$try = static function ( array $post ) use ( $confirm, $page, $user ): bool {
			$_POST = $post;
			try {
				return (bool) $confirm->invoke( $page, get_userdata( $user->ID ) );
			} finally {
				$_POST = array();
			}
		};
		$this->assertTrue( $try( array( 'password' => 'right-pass' ) ), 'no second factor: the password is enough' );

		$users  = Plugin::instance()->container()->get( UserTwoFactor::class );
		$secret = $users->pending_secret( $user->ID );
		$users->enable_totp( $user->ID, \SentinelShield\TwoFactor\Totp::code( $secret, intdiv( time(), 30 ) - 2 ), time() - 60 );
		$this->assertFalse( $try( array( 'password' => 'right-pass' ) ), 'with an app, the password alone is not enough' );
		$this->assertTrue( $try( array( 'password' => 'right-pass', 'code' => \SentinelShield\TwoFactor\Totp::code( $secret, intdiv( time(), 30 ) ) ) ) );

		for ( $i = 0; $i < 5; $i++ ) {
			$this->assertFalse( $try( array( 'password' => 'wrong' ) ) );
		}
		$this->assertFalse( $try( array( 'password' => 'right-pass', 'code' => \SentinelShield\TwoFactor\Totp::code( $secret, intdiv( time(), 30 ) + 1 ) ) ), 'locked after five failures, even with the right answers' );
		update_user_meta( $user->ID, UserTwoFactor::META . 'reauth_fails', array( time() - 1000 ) );
		$this->assertTrue( $try( array( 'password' => 'right-pass', 'code' => \SentinelShield\TwoFactor\Totp::code( $secret, intdiv( time(), 30 ) + 1 ) ) ), 'open again after 15 minutes' );
		wp_set_current_user( 0 );
	}

	/**
	 * Concurrency in the brute-force limits: while another login from the same
	 * IP is in progress, a parallel one is refused (not counted) instead of
	 * slipping past the limit check.
	 */
	public function test_parallel_logins_from_one_ip_are_serialized(): void {
		$c     = Plugin::instance()->container();
		$guard = new BruteForceGuard(
			self::settings( array( 'general' => array( 'test_mode' => false ) ) ),
			$c->get( LoginAttemptRepository::class ),
			$c->get( \SentinelShield\Firewall\Gate::class ),
			$c->get( EventRepository::class ),
			static fn(): string => '198.51.100.77',
			static fn(): bool => false,
			static fn() => null
		);
		$other = self::other_connection();
		$name  = 'login_ip_' . bin2hex( (string) inet_pton( '198.51.100.77' ) );
		$other->get_var( $other->prepare( 'SELECT GET_LOCK(%s, 0)', self::lock_name( $name ) ) );

		$result = $guard->authenticate( null, 'someone', 'pw' );
		$this->assertWPError( $result );
		$this->assertSame( BruteForceGuard::ERROR_CODE, $result->get_error_code() );
		$guard->failed( 'someone', $result );
		$this->assertSame( 0, $c->get( LoginAttemptRepository::class )->count_since( 0 ) );

		$other->query( $other->prepare( 'SELECT RELEASE_LOCK(%s)', self::lock_name( $name ) ) );
		$other->close();
		$this->assertNull( $guard->authenticate( null, 'someone', 'pw' ), 'Free again: checked normally.' );
		$this->assertTrue( Mutex::holds( $name ), 'Held until the attempt is counted.' );
		$guard->failed( 'someone', new \WP_Error( 'incorrect_password' ) );
		$this->assertFalse( Mutex::holds( $name ) );
		$this->assertSame( 1, $c->get( LoginAttemptRepository::class )->count_since( 0 ) );
	}

	public function test_cloudflare_ranges_come_from_the_public_api(): void {
		$body   = '';
		$fake   = static function ( $pre, $args, $url ) use ( &$body ) {
			return CloudflareRanges::URL === $url ? array(
				'response' => array( 'code' => 200 ),
				'body'     => $body,
			) : $pre;
		};
		$ranges = new CloudflareRanges();
		delete_site_option( CloudflareRanges::OPTION );
		add_filter( 'pre_http_request', $fake, 10, 3 );
		try {
			$body = (string) wp_json_encode( array( 'success' => true, 'result' => array( 'ipv4_cidrs' => array( '198.51.100.0/24' ), 'ipv6_cidrs' => array( '2001:db8::/32' ) ) ) );
			$this->assertWPError( $ranges->refresh(), 'a list that looks incomplete is refused' );
			$this->assertSame( CloudflareRanges::BUNDLED, $ranges->all() );
			$v4   = array( '192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24', '100.64.0.0/24', '100.64.1.0/24' );
			$body = (string) wp_json_encode( array( 'success' => true, 'result' => array( 'ipv4_cidrs' => array_merge( $v4, array( 'junk' ) ), 'ipv6_cidrs' => array( '2001:db8::/32', '2001:db9::/32' ) ) ) );
			$this->assertTrue( $ranges->refresh() );
			$this->assertSame( array_merge( $v4, array( '2001:db8::/32', '2001:db9::/32' ) ), $ranges->all() );
			$body = '{"success":false}';
			$this->assertWPError( $ranges->refresh() );
			$this->assertCount( 7, $ranges->all(), 'the last good list is kept' );
		} finally {
			remove_filter( 'pre_http_request', $fake, 10 );
			delete_site_option( CloudflareRanges::OPTION );
		}
	}
}
