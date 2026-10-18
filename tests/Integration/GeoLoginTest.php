<?php
/**
 * Login location restriction: decisions, sources, logging, test mode,
 * self-lockout protection and the database updater.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Tests\Integration;

use SentinelShield\Firewall\Gate;
use SentinelShield\Firewall\RuleCache;
use SentinelShield\Geo\CountryDatabase;
use SentinelShield\Geo\GeoResolver;
use SentinelShield\Geo\GeoUpdater;
use SentinelShield\Geo\LoginGeoGuard;
use SentinelShield\Modules\GeoLoginModule;
use SentinelShield\Net\Cidr;
use SentinelShield\Plugin;
use SentinelShield\Repository\BlockRepository;
use SentinelShield\Repository\EventRepository;
use SentinelShield\Settings;
use SentinelShield\SettingsSchema;
use SentinelShield\Support\Throttle;

final class GeoLoginTest extends \WP_UnitTestCase {

	use AdminUsers;

	private static string $dir;

	private string $ip = '8.8.8.8';

	/**
	 * Fake $_SERVER for the resolver.
	 *
	 * @var array<string, string>
	 */
	private array $server = array();

	/**
	 * Fake client IP details.
	 *
	 * @var array<string, mixed>
	 */
	private array $details = array();

	private ?LoginGeoGuard $guard = null;

	public static function set_up_before_class(): void {
		parent::set_up_before_class();
		self::$dir = sys_get_temp_dir() . '/ss-geo-it-' . bin2hex( random_bytes( 4 ) );
		mkdir( self::$dir );
		CountryDatabase::build( dirname( __DIR__ ) . '/fixtures/geo/country.csv', self::$dir . '/db.bin' );
	}

	public static function tear_down_after_class(): void {
		foreach ( (array) glob( self::$dir . '/{,.}*', GLOB_BRACE ) as $file ) {
			if ( is_file( (string) $file ) ) {
				CountryDatabase::close( (string) $file );
				unlink( (string) $file );
			}
		}
		rmdir( self::$dir );
		Plugin::instance()->container()->get( LoginGeoGuard::class )->register();
		parent::tear_down_after_class();
	}

	public function set_up(): void {
		parent::set_up();
		// The plugin registered its own guard at boot; test one instance at a time.
		self::unhook( Plugin::instance()->container()->get( LoginGeoGuard::class ) );
		global $wpdb;
		$wpdb->query( $wpdb->prepare( 'DELETE FROM %i', Plugin::instance()->container()->get( EventRepository::class )->table() ) );
		// Compiled rules live in the object cache, which the per-test rollback does not reset.
		Plugin::instance()->container()->get( RuleCache::class )->flush();
		// Log throttling remembers IPs for the whole PHP process.
		$seen = new \ReflectionProperty( Throttle::class, 'seen' );
		$seen->setAccessible( true );
		$seen->setValue( null, array() );
		$this->ip      = '8.8.8.8';
		$this->server  = array();
		$this->details = array( 'mode' => 'none' );
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

	private static function unhook( LoginGeoGuard $guard ): void {
		remove_filter( 'authenticate', array( $guard, 'authenticate' ), 99 );
		remove_action( 'wp_authenticate_application_password_errors', array( $guard, 'application_password' ) );
	}

	/**
	 * Saves settings and registers a guard reading the fixture database.
	 *
	 * @param array<string, mixed> $geo     geo.* settings.
	 * @param array<string, mixed> $modules modules.* settings.
	 */
	private function guard( array $geo, array $modules = array() ): LoginGeoGuard {
		update_site_option(
			Settings::OPTION,
			array(
				'general' => array( 'test_mode' => false ),
				'geo'     => $geo,
				'modules' => $modules,
			)
		);
		$c        = Plugin::instance()->container();
		$settings = $c->get( Settings::class );
		$settings->refresh();
		$resolver    = new GeoResolver( $settings, new CountryDatabase( self::$dir . '/db.bin' ), $this->server, fn(): array => $this->details );
		$this->guard = new LoginGeoGuard(
			$settings,
			$resolver,
			$c->get( Gate::class ),
			$c->get( EventRepository::class ),
			fn(): string => $this->ip,
			static fn(): bool => false
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

	public function test_allow_only_listed_countries(): void {
		self::factory()->user->create( array( 'user_login' => 'traveller', 'user_pass' => 'pw-right', 'role' => 'subscriber' ) );
		$this->guard( array( 'mode' => 'allow', 'countries' => 'US, GB' ) );

		$this->ip = '8.8.8.8';
		$this->assertInstanceOf( \WP_User::class, $this->login( 'traveller', 'pw-right' ) );
		$this->ip = '81.2.69.142';
		$this->assertInstanceOf( \WP_User::class, $this->login( 'traveller', 'pw-right' ) );

		$this->ip = '203.0.113.9';
		$right = $this->login( 'traveller', 'pw-right' );
		$wrong = $this->login( 'traveller', 'pw-wrong' );
		$this->assertWPError( $right );
		$this->assertSame( LoginGeoGuard::ERROR_CODE, $right->get_error_code() );
		// Same answer for a wrong password: the form cannot be used to test passwords.
		$this->assertSame( array( LoginGeoGuard::ERROR_CODE ), $wrong->get_error_codes() );
		$this->assertStringContainsString( 'db-ip.com', $right->get_error_message() );

		$events = $this->events();
		$this->assertSame( 'login_denied', $events[0]['event'] );
		$this->assertStringContainsString( 'FR (France)', $events[0]['reason'] );
		$this->assertStringContainsString( 'traveller', $events[0]['reason'] );
		$this->assertCount( 1, $events, 'one row per IP per minute' );
	}

	public function test_block_listed_countries_and_ipv6(): void {
		self::factory()->user->create( array( 'user_login' => 'u6', 'user_pass' => 'pw' ) );
		$this->guard( array( 'mode' => 'block', 'countries' => 'FR DE' ) );
		$this->ip = '203.0.113.9';
		$this->assertWPError( $this->login( 'u6', 'pw' ) );
		$this->ip = '2a00:1450:4001:80b::200e';
		$this->assertWPError( $this->login( 'u6', 'pw' ) );
		$this->ip = '2001:4860:4860::8888';
		$this->assertInstanceOf( \WP_User::class, $this->login( 'u6', 'pw' ) );
	}

	public function test_scope_administrators_only(): void {
		self::factory()->user->create( array( 'user_login' => 'member', 'user_pass' => 'pw', 'role' => 'subscriber' ) );
		self::create_admin( array( 'user_login' => 'boss', 'user_pass' => 'pw', 'user_email' => 'boss@example.test' ) );
		$this->guard( array( 'mode' => 'allow', 'countries' => 'US', 'scope' => 'privileged' ) );
		$this->ip = '203.0.113.9';
		$this->assertInstanceOf( \WP_User::class, $this->login( 'member', 'pw' ) );
		$this->assertWPError( $this->login( 'boss', 'pw' ) );
		$this->assertSame( LoginGeoGuard::ERROR_CODE, $this->login( 'boss@example.test', 'wrong' )->get_error_code(), 'email login is matched too' );
		$this->assertNotSame( LoginGeoGuard::ERROR_CODE, $this->login( 'nobody', 'pw' )->get_error_code(), 'unknown account is out of scope' );

		$this->guard( array( 'mode' => 'allow', 'countries' => 'US', 'scope' => 'all' ) );
		$this->assertSame( LoginGeoGuard::ERROR_CODE, $this->login( 'nobody', 'pw' )->get_error_code() );
	}

	public function test_unknown_country_policy(): void {
		self::factory()->user->create( array( 'user_login' => 'local', 'user_pass' => 'pw' ) );
		$this->ip = '10.1.2.3';
		$this->guard( array( 'mode' => 'allow', 'countries' => 'US' ) );
		$this->assertInstanceOf( \WP_User::class, $this->login( 'local', 'pw' ) );
		$this->guard( array( 'mode' => 'allow', 'countries' => 'US', 'unknown' => 'deny' ) );
		$this->assertWPError( $this->login( 'local', 'pw' ) );
		$this->assertSame( 'unknown_denied', $this->guard->check( '1.0.5.0', null )['reason'], 'gap in the database' );
		$this->assertSame( array( 'invalid', 'unknown_denied' ), array_values( array_intersect_key( $this->guard->check( '', null ), array_flip( array( 'reason', 'source' ) ) ) ), 'unusable IP is unknown, not allowlisted' );
	}

	public function test_allowlist_and_empty_list_and_off_never_deny(): void {
		self::factory()->user->create( array( 'user_login' => 'ok', 'user_pass' => 'pw' ) );
		$this->ip = '203.0.113.9';
		$this->guard( array( 'mode' => 'allow', 'countries' => '' ) );
		$this->assertInstanceOf( \WP_User::class, $this->login( 'ok', 'pw' ), 'no countries: not configured' );
		$this->guard( array( 'mode' => 'off', 'countries' => 'US' ) );
		$this->assertInstanceOf( \WP_User::class, $this->login( 'ok', 'pw' ) );

		$c = Plugin::instance()->container();
		$c->get( BlockRepository::class )->add( 'allow', Cidr::parse( '203.0.113.9' ), 'test', 'manual' );
		$c->get( RuleCache::class )->flush();
		$this->guard( array( 'mode' => 'allow', 'countries' => 'US' ) );
		$this->assertInstanceOf( \WP_User::class, $this->login( 'ok', 'pw' ) );
		$this->assertSame( 'allowlist', $this->guard->check( '203.0.113.9', null )['reason'] );
	}

	public function test_test_mode_only_logs(): void {
		self::factory()->user->create( array( 'user_login' => 'tm', 'user_pass' => 'pw' ) );
		$this->ip = '203.0.113.9';
		$this->guard( array( 'mode' => 'allow', 'countries' => 'US' ), array( 'geo_login' => array( 'test_mode' => 'on' ) ) );
		$this->assertInstanceOf( \WP_User::class, $this->login( 'tm', 'pw' ) );
		$events = $this->events();
		$this->assertSame( 'would_deny_login', $events[0]['event'] );
		$this->assertSame( '1', (string) $events[0]['is_test'] );
	}

	public function test_cloudflare_header_only_from_cloudflare(): void {
		self::factory()->user->create( array( 'user_login' => 'cf', 'user_pass' => 'pw' ) );
		$this->ip     = '8.8.8.8';
		$this->server = array( 'HTTP_CF_IPCOUNTRY' => 'fr' );

		// Header sent directly, not through Cloudflare: ignored, database says US.
		$this->details = array( 'mode' => 'cloudflare', 'remote_trusted' => false, 'ip' => '8.8.8.8' );
		$guard         = $this->guard( array( 'mode' => 'allow', 'countries' => 'US' ) );
		$this->assertSame( array( 'US', 'dbip' ), array_values( array_intersect_key( $guard->check( '8.8.8.8', null, true ), array_flip( array( 'country', 'source' ) ) ) ) );

		$this->details = array( 'mode' => 'cloudflare', 'remote_trusted' => true, 'fallback' => false, 'ip' => '8.8.8.8' );
		$check         = $guard->check( '8.8.8.8', null, true );
		$this->assertSame( 'FR', $check['country'] );
		$this->assertSame( 'cloudflare', $check['source'] );
		$this->assertWPError( $this->login( 'cf', 'pw' ) );
		$this->assertSame( 'US', $guard->check( '8.8.8.8', null, false )['country'], 'other IPs use the database' );
	}

	public function test_server_variable(): void {
		$this->server = array( 'GEOIP_COUNTRY_CODE' => 'GB' );
		$guard        = $this->guard( array( 'mode' => 'allow', 'countries' => 'GB', 'server_var' => 'GEOIP_COUNTRY_CODE' ) );
		$check        = $guard->check( '203.0.113.9', null, true );
		$this->assertSame( array( 'GB', 'server', true ), array( $check['country'], $check['source'], $check['allowed'] ) );
	}

	public function test_application_passwords_are_checked(): void {
		$user = self::create_admin_user();
		$this->ip = '203.0.113.9';
		$this->guard( array( 'mode' => 'allow', 'countries' => 'US' ) );
		$error = new \WP_Error();
		do_action( 'wp_authenticate_application_password_errors', $error, $user, array(), 'secret' );
		$this->assertContains( LoginGeoGuard::ERROR_CODE, $error->get_error_codes() );
	}

	public function test_settings_sanitizing(): void {
		[ $codes, $error ] = SettingsSchema::sanitize_field( (array) SettingsSchema::field( 'geo.countries' ), 'us, xx gb GB' );
		$this->assertSame( 'US, GB', $codes );
		$this->assertStringContainsString( 'XX', (string) $error );
		$this->assertSame( 'GEOIP_COUNTRY_CODE', SettingsSchema::sanitize_field( (array) SettingsSchema::field( 'geo.server_var' ), 'geoip_country_code!' )[0] );
	}

	public function test_saving_settings_that_deny_yourself_switches_to_test_mode(): void {
		$c     = Plugin::instance()->container();
		$admin = self::create_admin();
		wp_set_current_user( $admin );
		$c->instance( 'client_ip', '203.0.113.9' );
		$c->instance( 'client_ip_details', array( 'ip' => '203.0.113.9', 'mode' => 'none', 'fallback' => false ) );
		$c->instance( CountryDatabase::class, new CountryDatabase( self::$dir . '/db.bin' ) );
		$c->set( GeoResolver::class, static fn( $c ) => new GeoResolver( $c->get( Settings::class ), $c->get( CountryDatabase::class ), array(), static fn(): array => (array) $c->get( 'client_ip_details' ) ) );
		$c->set( LoginGeoGuard::class, static fn( $c ) => new LoginGeoGuard( $c->get( Settings::class ), $c->get( GeoResolver::class ), $c->get( Gate::class ), $c->get( EventRepository::class ), static fn(): string => (string) $c->get( 'client_ip' ), static fn(): bool => false ) );
		try {
			$settings = $c->get( Settings::class );
			$all      = $settings->network_settings();
			$all['general']['test_mode'] = false;
			$all['geo']['mode']          = 'allow';
			$all['geo']['countries']     = 'US';
			$settings->save_network( $all );
			GeoLoginModule::protect_current_admin( $c );
			$this->assertSame( 'on', $settings->get( 'modules.geo_login.test_mode' ) );

			// Allowed from here: nothing changes.
			$all['modules']['geo_login']['test_mode'] = 'off';
			$all['geo']['countries']                  = 'US, FR';
			$settings->save_network( $all );
			GeoLoginModule::protect_current_admin( $c );
			$this->assertSame( 'off', $settings->get( 'modules.geo_login.test_mode' ) );

			// Denied by country; the automatic administrator allowlist entry does not
			// exempt from login rules, so this still switches to test mode.
			$all['geo']['countries'] = 'US';
			$settings->save_network( $all );
			$c->get( BlockRepository::class )->add( 'allow', Cidr::parse( '203.0.113.9' ), 'admin', 'admin_auto' );
			$c->get( RuleCache::class )->flush();
			GeoLoginModule::protect_current_admin( $c );
			$this->assertSame( 'on', $settings->get( 'modules.geo_login.test_mode' ) );

			// An allowlist entry added by hand does exempt: nothing changes.
			$all['modules']['geo_login']['test_mode'] = 'off';
			$settings->save_network( $all );
			$c->get( BlockRepository::class )->add( 'allow', Cidr::parse( '203.0.113.9' ), 'my office', 'manual' );
			$c->get( RuleCache::class )->flush();
			GeoLoginModule::protect_current_admin( $c );
			$this->assertSame( 'off', $settings->get( 'modules.geo_login.test_mode' ) );
		} finally {
			$c->set( 'client_ip_details', static fn( $c ): array => $c->get( \SentinelShield\Net\ClientIpFactory::class )->from_globals()->details() );
			$c->set( 'client_ip', static fn( $c ): string => (string) $c->get( 'client_ip_details' )['ip'] );
			$c->set( CountryDatabase::class, static fn(): CountryDatabase => new CountryDatabase( GeoUpdater::path() ) );
			$c->set( GeoResolver::class, static fn( $c ) => new GeoResolver( $c->get( Settings::class ), $c->get( CountryDatabase::class ), array(), static fn(): array => (array) $c->get( 'client_ip_details' ) ) );
			$c->set( LoginGeoGuard::class, static fn( $c ) => new LoginGeoGuard( $c->get( Settings::class ), $c->get( GeoResolver::class ), $c->get( Gate::class ), $c->get( EventRepository::class ), static fn(): string => (string) $c->get( 'client_ip' ), static fn(): bool => false ) );
		}
	}

	public function test_updater_downloads_falls_back_a_month_and_keeps_old_data_on_failure(): void {
		update_site_option( Settings::OPTION, array( 'geo' => array( 'dbip' => true ) ) );
		$c        = Plugin::instance()->container();
		$settings = $c->get( Settings::class );
		$settings->refresh();
		$db      = new CountryDatabase( self::$dir . '/dl.bin' );
		$updater = new GeoUpdater( $settings, $db, $c->get( EventRepository::class ), 5 );
		delete_site_option( GeoUpdater::STATE_OPTION );
		$this->assertTrue( $updater->due() );

		$gz       = (string) gzencode( (string) file_get_contents( dirname( __DIR__ ) . '/fixtures/geo/country.csv' ) );
		$requests = array();
		$reply    = static function ( string $url, array $args ) use ( &$requests, &$gz ): array {
			$requests[] = array( $url, $args['headers'] ?? array() );
			if ( str_contains( $url, gmdate( 'Y-m' ) ) ) {
				return array( 'response' => array( 'code' => 404 ), 'body' => '', 'headers' => array() );
			}
			if ( ! empty( $args['headers']['If-None-Match'] ) ) {
				return array( 'response' => array( 'code' => 304 ), 'body' => '', 'headers' => array() );
			}
			file_put_contents( $args['filename'], $gz );
			return array( 'response' => array( 'code' => 200 ), 'body' => '', 'headers' => array( 'etag' => '"v1"' ) );
		};
		$filter = static fn( $pre, array $args, string $url ) => $reply( $url, $args );
		add_filter( 'pre_http_request', $filter, 10, 3 );
		try {
			$state = $updater->update();
			$this->assertIsArray( $state, is_wp_error( $state ) ? $state->get_error_message() : '' );
			$this->assertSame( gmdate( 'Y-m', strtotime( 'first day of last month' ) ), $state['month'] );
			$this->assertSame( 'FR', $db->lookup( (string) inet_pton( '203.0.113.1' ) ) );
			$this->assertFileExists( self::$dir . '/.htaccess' );
			$this->assertFalse( $updater->due() );

			// Unchanged: a conditional request, nothing rebuilt.
			$this->assertIsArray( $updater->update() );
			$this->assertSame( '"v1"', end( $requests )[1]['If-None-Match'] ?? null );

			// A truncated download is refused and the working database stays.
			$gz = (string) gzencode( "8.8.8.0,8.8.8.255,US\n" );
			$this->assertWPError( $updater->update( true ) );
			$this->assertSame( 'FR', $db->lookup( (string) inet_pton( '203.0.113.1' ) ) );
			$this->assertNotEmpty( $updater->state()['error'] );

			$updater->purge();
			$this->assertNull( $db->info() );
		} finally {
			remove_filter( 'pre_http_request', $filter, 10 );
			delete_site_option( GeoUpdater::STATE_OPTION );
		}
	}
}
