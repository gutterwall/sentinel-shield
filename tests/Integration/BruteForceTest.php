<?php
/**
 * Login brute-force protection: per-IP and per-account limits, lockouts,
 * instant usernames, test mode, generic errors and the real login path.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Tests\Integration;

use SentinelShield\Firewall\Gate;
use SentinelShield\Firewall\RuleCache;
use SentinelShield\Geo\LoginGeoGuard;
use SentinelShield\Lockout\Lockout;
use SentinelShield\Login\BruteForceGuard;
use SentinelShield\Modules\LockoutModule;
use SentinelShield\Net\Cidr;
use SentinelShield\Plugin;
use SentinelShield\Repository\BlockRepository;
use SentinelShield\Repository\EventRepository;
use SentinelShield\Repository\LoginAttemptRepository;
use SentinelShield\Settings;
use SentinelShield\Support\Throttle;

final class BruteForceTest extends \WP_UnitTestCase {

	private string $ip = '198.51.100.7';

	private int $now = 1800000000;

	/**
	 * Lockouts requested: [ip, module, reason].
	 *
	 * @var list<array{0:string, 1:string, 2:string}>
	 */
	private array $locks = array();

	/**
	 * What the fake lockout returns: 'real', 'test' or 'off' (null).
	 *
	 * @var string
	 */
	private string $lock_result = 'real';

	private ?BruteForceGuard $guard = null;

	public static function tear_down_after_class(): void {
		Plugin::instance()->container()->get( BruteForceGuard::class )->register();
		parent::tear_down_after_class();
	}

	public function set_up(): void {
		parent::set_up();
		self::unhook( Plugin::instance()->container()->get( BruteForceGuard::class ) );
		$c = Plugin::instance()->container();
		global $wpdb;
		$wpdb->query( $wpdb->prepare( 'DELETE FROM %i', $c->get( EventRepository::class )->table() ) );
		$wpdb->query( $wpdb->prepare( 'DELETE FROM %i', $c->get( LoginAttemptRepository::class )->table() ) );
		$c->get( RuleCache::class )->flush();
		$seen = new \ReflectionProperty( Throttle::class, 'seen' );
		$seen->setAccessible( true );
		$seen->setValue( null, array() );
		$this->locks       = array();
		$this->lock_result = 'real';
		$this->ip          = '198.51.100.7';
	}

	public function tear_down(): void {
		if ( null !== $this->guard ) {
			self::unhook( $this->guard );
		}
		delete_site_option( Settings::OPTION );
		Plugin::instance()->container()->get( Settings::class )->refresh();
		parent::tear_down();
		Plugin::instance()->container()->get( RuleCache::class )->flush();
	}

	private static function unhook( BruteForceGuard $guard ): void {
		remove_filter( 'authenticate', array( $guard, 'authenticate' ), 95 );
		remove_filter( 'authenticate', array( $guard, 'generic_error' ), 100 );
		remove_action( 'wp_authenticate_application_password_errors', array( $guard, 'application_password' ) );
		remove_action( 'wp_login_failed', array( $guard, 'failed' ) );
		remove_action( 'wp_login', array( $guard, 'succeeded' ) );
		remove_filter( 'xmlrpc_enabled', '__return_false' );
	}

	/**
	 * Saves settings and registers a guard with a fake IP, clock and lockout.
	 *
	 * @param array<string, mixed> $login   login.* settings.
	 * @param array<string, mixed> $modules modules.* settings.
	 * @param bool                 $real    Use the real lockout module instead of the fake.
	 */
	private function guard( array $login = array(), array $modules = array(), bool $real = false ): BruteForceGuard {
		if ( null !== $this->guard ) {
			self::unhook( $this->guard );
		}
		update_site_option(
			Settings::OPTION,
			array(
				'general' => array( 'test_mode' => false ),
				'login'   => $login,
				'modules' => $modules,
			)
		);
		$c        = Plugin::instance()->container();
		$settings = $c->get( Settings::class );
		$settings->refresh();
		$lockout     = $real
			? static fn( string $ip, string $module, string $reason ): ?Lockout => LockoutModule::apply( $c, $ip, $module, $reason )
			: function ( string $ip, string $module, string $reason ): ?Lockout {
				$this->locks[] = array( $ip, $module, $reason );
				if ( 'off' === $this->lock_result ) {
					return null;
				}
				return new Lockout( $ip, 1, 900, $this->now + 900, 'test' === $this->lock_result, $module, $reason );
			};
		$this->guard = new BruteForceGuard(
			$settings,
			$c->get( LoginAttemptRepository::class ),
			$c->get( Gate::class ),
			$c->get( EventRepository::class ),
			fn(): string => $this->ip,
			static fn(): bool => false,
			$lockout,
			$real ? null : fn(): int => $this->now
		);
		$this->guard->register();
		return $this->guard;
	}

	private function login( string $user, string $pass ): \WP_User|\WP_Error {
		return wp_authenticate( $user, $pass );
	}

	/**
	 * @return list<array<string, mixed>>
	 */
	private function events(): array {
		return Plugin::instance()->container()->get( EventRepository::class )->query( array() )[0];
	}

	public function test_ip_limit_locks_out_and_refuses_the_rest_of_the_request(): void {
		self::factory()->user->create( array( 'user_login' => 'alice', 'user_pass' => 'right' ) );
		$this->guard( array( 'max_failures' => 3 ) );

		$this->assertWPError( $this->login( 'alice', 'wrong1' ) );
		$this->assertWPError( $this->login( 'alice', 'wrong2' ) );
		$this->assertSame( array(), $this->locks );
		$this->assertInstanceOf( \WP_User::class, $this->login( 'alice', 'right' ), 'under the limit' );
		$this->assertWPError( $this->login( 'bob', 'x' ) );

		$this->assertCount( 1, $this->locks );
		$this->assertSame( array( '198.51.100.7', 'login_guard' ), array_slice( $this->locks[0], 0, 2 ) );
		$this->assertStringContainsString( '3 failed logins within 15 minutes', $this->locks[0][2] );

		// Same request (think XML-RPC multicall): even the right password is refused now.
		$right = $this->login( 'alice', 'right' );
		$wrong = $this->login( 'alice', 'nope' );
		$this->assertSame( array( BruteForceGuard::ERROR_CODE ), $right->get_error_codes() );
		$this->assertSame( array( BruteForceGuard::ERROR_CODE ), $wrong->get_error_codes(), 'same answer whatever the password' );
		$this->assertCount( 1, $this->locks, 'refusals are not counted as new failures' );

		// The lockout took over, so the count restarted.
		$repo = Plugin::instance()->container()->get( LoginAttemptRepository::class );
		$this->assertSame( 0, $repo->count_ip( (string) inet_pton( '198.51.100.7' ), 0 ) );
		$this->assertSame( 'login_denied', $this->events()[0]['event'] );

		// Another IP is unaffected.
		$this->ip = '198.51.100.8';
		$this->assertInstanceOf( \WP_User::class, $this->login( 'alice', 'right' ) );
	}

	public function test_without_lockouts_the_count_refuses_until_it_ages_out(): void {
		self::factory()->user->create( array( 'user_login' => 'carol', 'user_pass' => 'right' ) );
		$this->lock_result = 'off';
		$this->guard( array( 'max_failures' => 2, 'window_minutes' => 10 ) );
		$this->login( 'carol', 'a' );
		$this->login( 'carol', 'b' );
		$this->assertSame( BruteForceGuard::ERROR_CODE, $this->login( 'carol', 'right' )->get_error_code() );
		$this->assertContains( 'login_limit', array_column( $this->events(), 'event' ) );

		$this->now += 11 * MINUTE_IN_SECONDS;
		$this->assertInstanceOf( \WP_User::class, $this->login( 'carol', 'right' ), 'failures aged out' );
	}

	public function test_real_lockout_blocks_the_ip(): void {
		self::factory()->user->create( array( 'user_login' => 'dave', 'user_pass' => 'right' ) );
		$this->guard( array( 'max_failures' => 2 ), array(), true );
		$this->login( 'dave', 'a' );
		$this->login( 'dave', 'b' );
		$c = Plugin::instance()->container();
		$c->get( RuleCache::class )->flush();
		$decision = $c->get( Gate::class )->evaluate( '198.51.100.7', '/', false, true );
		$this->assertTrue( $decision->is_block(), 'the IP is blocked site-wide' );
		$this->assertContains( 'lockout', array_column( $this->events(), 'event' ) );
	}

	public function test_account_limit_allows_known_ips_only(): void {
		$id = self::factory()->user->create( array( 'user_login' => 'erin', 'user_pass' => 'right', 'user_email' => 'erin@example.test' ) );
		$this->guard( array( 'max_failures' => 50, 'account_max_failures' => 4 ) );

		// The real user logs in once from home.
		$this->ip = '192.0.2.10';
		$this->assertInstanceOf( \WP_User::class, $this->login( 'erin', 'right' ) );
		do_action( 'wp_login', 'erin', get_userdata( $id ) );
		$this->assertArrayHasKey( '192.0.2.10', BruteForceGuard::known_ips( get_userdata( $id ) ) );

		// A botnet tries a few passwords each, by login and by email.
		foreach ( array( '203.0.113.1', '203.0.113.2', '203.0.113.3', '203.0.113.4' ) as $i => $bot ) {
			$this->ip = $bot;
			$this->login( 0 === $i % 2 ? 'erin' : 'erin@example.test', 'guess' );
		}
		$this->assertSame( array(), $this->locks, 'no IP is locked out' );
		$this->ip = '203.0.113.5';
		$this->assertSame( BruteForceGuard::ERROR_CODE, $this->login( 'erin', 'right' )->get_error_code(), 'new IP refused even with the right password' );
		$this->assertSame( BruteForceGuard::ERROR_CODE, $this->login( 'ERIN@example.test', 'x' )->get_error_code(), 'email counts as the same account' );
		$this->assertContains( 'account_attack', array_column( $this->events(), 'event' ) );

		$this->ip = '192.0.2.10';
		$this->assertInstanceOf( \WP_User::class, $this->login( 'erin', 'right' ), 'known IP still gets in' );
		$this->assertSame( 'known_ip', $this->guard->check( '192.0.2.10', 'erin' )['reason'] );

		// Other accounts are unaffected.
		self::factory()->user->create( array( 'user_login' => 'frank', 'user_pass' => 'pw' ) );
		$this->ip = '203.0.113.5';
		$this->assertInstanceOf( \WP_User::class, $this->login( 'frank', 'pw' ) );
		// 0 switches the account limit off.
		$this->guard( array( 'max_failures' => 50, 'account_max_failures' => 0 ) );
		$this->assertInstanceOf( \WP_User::class, $this->login( 'erin', 'right' ) );
	}

	public function test_names_without_accounts_are_counted_without_revealing_anything(): void {
		$this->guard( array( 'max_failures' => 50, 'account_max_failures' => 2 ) );
		$this->assertSame( 'n:ghost', BruteForceGuard::account_key( ' Ghost ' ) );
		foreach ( array( '203.0.113.1', '203.0.113.2' ) as $bot ) {
			$this->ip = $bot;
			$this->login( 'ghost', 'x' );
		}
		$this->ip = '203.0.113.3';
		$this->assertSame( BruteForceGuard::ERROR_CODE, $this->login( 'ghost', 'x' )->get_error_code(), 'same refusal as a real account' );
	}

	public function test_allowlisted_ip_is_never_counted_or_refused(): void {
		self::factory()->user->create( array( 'user_login' => 'gina', 'user_pass' => 'right' ) );
		$c = Plugin::instance()->container();
		$c->get( BlockRepository::class )->add( 'allow', Cidr::parse( '198.51.100.7' ), 'office', 'manual' );
		$c->get( RuleCache::class )->flush();
		$this->guard( array( 'max_failures' => 2, 'account_max_failures' => 2 ) );
		for ( $i = 0; $i < 5; $i++ ) {
			$this->login( 'gina', 'wrong' );
		}
		$this->assertSame( array(), $this->locks );
		$this->assertInstanceOf( \WP_User::class, $this->login( 'gina', 'right' ) );
		$this->assertSame( 0, $c->get( LoginAttemptRepository::class )->count_since( 0 ) );
	}

	public function test_instant_usernames(): void {
		self::factory()->user->create( array( 'user_login' => 'root', 'user_pass' => 'pw' ) );
		$this->guard( array( 'instant_usernames' => "Admin, test\nroot" ) );
		$this->assertSame( array( 'admin', 'test', 'root' ), BruteForceGuard::instant_usernames( Plugin::instance()->container()->get( Settings::class ) ) );
		$this->login( 'root', 'wrong' );
		$this->assertSame( array(), $this->locks, 'a name that is a real account is ignored' );
		$this->login( 'admin', 'x' );
		$this->assertSame( array(), $this->locks, 'the test site has an admin account' );
		$this->login( 'Test', 'x' );
		$this->assertCount( 1, $this->locks );
		// Multisite lowercases usernames in sanitize_user().
		$this->assertStringContainsStringIgnoringCase( '"Test"', $this->locks[0][2] );
	}

	public function test_test_mode_logs_without_refusing(): void {
		self::factory()->user->create( array( 'user_login' => 'hank', 'user_pass' => 'right' ) );
		$this->lock_result = 'test';
		$this->guard( array( 'max_failures' => 2 ), array( 'login_guard' => array( 'test_mode' => 'on' ) ) );
		$this->login( 'hank', 'a' );
		$this->login( 'hank', 'b' );
		$this->assertCount( 1, $this->locks );
		$this->assertInstanceOf( \WP_User::class, $this->login( 'hank', 'right' ), 'a test lockout does not refuse' );

		$this->lock_result = 'off';
		$this->guard( array( 'max_failures' => 2 ), array( 'login_guard' => array( 'test_mode' => 'on' ) ) );
		$this->login( 'hank', 'c' );
		$this->login( 'hank', 'd' );
		$this->assertInstanceOf( \WP_User::class, $this->login( 'hank', 'right' ) );
		$this->assertContains( 'would_deny_login', array_column( $this->events(), 'event' ) );
	}

	public function test_generic_errors_hide_which_accounts_exist(): void {
		self::factory()->user->create( array( 'user_login' => 'ivy', 'user_pass' => 'right', 'user_email' => 'ivy@example.test' ) );
		$this->guard( array( 'max_failures' => 50 ) );
		$unknown = $this->login( 'nobody', 'x' );
		$wrong   = $this->login( 'ivy', 'x' );
		$email   = $this->login( 'nobody@example.test', 'x' );
		$this->assertSame( array( BruteForceGuard::ERROR_INVALID ), $unknown->get_error_codes() );
		$this->assertSame( $unknown->get_error_messages(), $wrong->get_error_messages() );
		$this->assertSame( $unknown->get_error_messages(), $email->get_error_messages() );
		$this->assertStringNotContainsString( 'ivy', $wrong->get_error_message() );
		$this->assertSame( 3, Plugin::instance()->container()->get( LoginAttemptRepository::class )->count_since( 0 ), 'still counted' );
		$this->assertContains( BruteForceGuard::ERROR_INVALID, apply_filters( 'shake_error_codes', array() ) );

		$this->guard( array( 'max_failures' => 50, 'generic_errors' => false ) );
		$this->assertSame( 'incorrect_password', $this->login( 'ivy', 'x' )->get_error_code() );
	}

	public function test_own_and_location_refusals_are_not_counted(): void {
		$this->guard();
		$this->guard->failed( 'x', new \WP_Error( BruteForceGuard::ERROR_CODE ) );
		$this->guard->failed( 'x', new \WP_Error( LoginGeoGuard::ERROR_CODE ) );
		$this->assertSame( 0, Plugin::instance()->container()->get( LoginAttemptRepository::class )->count_since( 0 ) );
		$this->guard->failed( 'x', new \WP_Error( 'sentinel_shield_2fa_failed' ) );
		$this->assertSame( 1, Plugin::instance()->container()->get( LoginAttemptRepository::class )->count_since( 0 ), 'wrong two-factor codes count' );
	}

	public function test_application_passwords_and_xmlrpc_switch(): void {
		$id = self::factory()->user->create( array( 'user_login' => 'jack' ) );
		$this->lock_result = 'off';
		$this->guard( array( 'max_failures' => 1 ) );
		$this->login( 'jack', 'wrong' );
		$error = new \WP_Error();
		do_action( 'wp_authenticate_application_password_errors', $error, get_userdata( $id ), array(), '' );
		$this->assertSame( array( BruteForceGuard::ERROR_CODE ), $error->get_error_codes() );

		$this->assertTrue( apply_filters( 'xmlrpc_enabled', true ) );
		$this->guard( array( 'disable_xmlrpc' => true ) );
		$this->assertFalse( apply_filters( 'xmlrpc_enabled', true ) );
	}
}
