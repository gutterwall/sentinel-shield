<?php
/**
 * Application password policy and the enforcement health checks.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Tests\Integration;

use SentinelShield\Login\AppPasswordPolicy;
use SentinelShield\Plugin;
use SentinelShield\Safety\Health;
use SentinelShield\Settings;
use SentinelShield\Support\Mutex;

final class HealthAndPolicyTest extends \WP_UnitTestCase {

	use AdminUsers;

	private ?AppPasswordPolicy $policy = null;

	public function tear_down(): void {
		if ( null !== $this->policy ) {
			remove_filter( 'wp_is_application_passwords_available_for_user', array( $this->policy, 'available_for_user' ) );
			remove_action( 'wp_authenticate_application_password_errors', array( $this->policy, 'check_age' ) );
		}
		remove_filter( 'wp_is_application_passwords_available', '__return_true' );
		remove_filter( 'application_password_is_api_request', '__return_true' );
		unset( $_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW'] );
		delete_site_option( Settings::OPTION );
		delete_site_option( Mutex::HEALTH_OPTION );
		Plugin::instance()->container()->get( Settings::class )->refresh();
		parent::tear_down();
	}

	/**
	 * Saves settings and returns them.
	 *
	 * @param array<string, mixed> $values Settings.
	 */
	private static function settings( array $values ): Settings {
		update_site_option( Settings::OPTION, $values );
		$settings = Plugin::instance()->container()->get( Settings::class );
		$settings->refresh();
		return $settings;
	}

	private function policy( array $login ): void {
		$this->policy = new AppPasswordPolicy( self::settings( array( 'login' => $login ) ) );
		$this->policy->register();
	}

	/**
	 * Authenticates like the REST API does with HTTP Basic credentials.
	 */
	private static function rest_login( string $login, string $password ): int|false {
		wp_set_current_user( 0 );
		$_SERVER['PHP_AUTH_USER'] = $login;
		$_SERVER['PHP_AUTH_PW']   = $password;
		return wp_validate_application_password( false );
	}

	public function test_who_may_use_application_passwords(): void {
		$admin = self::create_admin_user();
		$user  = self::factory()->user->create_and_get();

		$this->policy( array( 'app_passwords' => 'non_privileged' ) );
		$this->assertFalse( apply_filters( 'wp_is_application_passwords_available_for_user', true, $admin ) );
		$this->assertTrue( apply_filters( 'wp_is_application_passwords_available_for_user', true, $user ) );

		$this->policy( array( 'app_passwords' => 'off' ) );
		$this->assertFalse( apply_filters( 'wp_is_application_passwords_available_for_user', true, $user ) );

		$this->policy( array( 'app_passwords' => 'all' ) );
		$this->assertTrue( apply_filters( 'wp_is_application_passwords_available_for_user', true, $admin ) );
	}

	public function test_old_and_unused_application_passwords_stop_working(): void {
		add_filter( 'wp_is_application_passwords_available', '__return_true' );
		add_filter( 'application_password_is_api_request', '__return_true' );
		$user = self::factory()->user->create_and_get( array( 'user_login' => 'integration' ) );
		[ $password, $item ] = \WP_Application_Passwords::create_new_application_password( $user->ID, array( 'name' => 'old' ) );
		$this->policy( array( 'app_password_max_days' => 30 ) );
		$this->assertSame( $user->ID, self::rest_login( 'integration', $password ), 'new enough' );

		// WordPress's own update method cannot change the creation time; edit the stored record.
		$age = static function ( int $created, int $used ) use ( $user, $item ): void {
			$all = (array) get_user_meta( $user->ID, \WP_Application_Passwords::USERMETA_KEY_APPLICATION_PASSWORDS, true );
			foreach ( $all as &$stored ) {
				if ( $stored['uuid'] === $item['uuid'] ) {
					$stored['created']   = $created;
					$stored['last_used'] = $used;
				}
			}
			unset( $stored );
			update_user_meta( $user->ID, \WP_Application_Passwords::USERMETA_KEY_APPLICATION_PASSWORDS, $all );
		};
		$age( time() - 40 * DAY_IN_SECONDS, time() );
		$this->assertFalse( self::rest_login( 'integration', $password ), 'older than the maximum age' );

		$this->policy( array( 'app_password_unused_days' => 90 ) );
		$this->assertSame( $user->ID, self::rest_login( 'integration', $password ), 'old but in use' );
		$age( time() - 400 * DAY_IN_SECONDS, time() - 100 * DAY_IN_SECONDS );
		$this->assertFalse( self::rest_login( 'integration', $password ), 'unused for 100 days' );
		$stored = \WP_Application_Passwords::get_user_application_password( $user->ID, $item['uuid'] );
		$this->assertSame( 'unused', AppPasswordPolicy::status( (array) $stored, Plugin::instance()->container()->get( Settings::class ) ) );
	}

	public function test_health_reports_test_mode_locks_and_findings(): void {
		$health = new Health( Plugin::instance()->container() );
		$by_id  = static fn( array $checks ): array => array_column( $checks, null, 'id' );

		self::settings( array() );
		$checks = $by_id( $health->checks() );
		$this->assertSame( 'warn', $checks['enabled']['state'], 'fresh installs are in open-ended test mode' );
		$this->assertStringContainsString( 'no end date', $checks['enabled']['detail'] );

		self::settings( array( 'general' => array( 'test_mode' => false ) ) );
		$checks = $by_id( $health->checks() );
		$this->assertSame( 'ok', $checks['enabled']['state'] );

		self::settings(
			array(
				'general' => array( 'test_mode' => false ),
				'modules' => array( 'login_guard' => array( 'test_mode' => 'on' ) ),
			)
		);
		$this->assertStringContainsString( 'login_guard', $by_id( $health->checks() )['enabled']['detail'] );

		self::settings( array( 'general' => array( 'enabled' => false ) ) );
		$checks = $health->checks();
		$this->assertSame( 'bad', $by_id( $checks )['enabled']['state'] );
		$this->assertSame( 'bad', Health::overall( $checks ) );

		self::settings( array( 'general' => array( 'test_mode' => false ) ) );
		update_site_option(
			Mutex::HEALTH_OPTION,
			array(
				'mode'  => 'failed',
				'time'  => time(),
				'error' => 'Lost connection',
			)
		);
		$checks = $by_id( $health->checks() );
		$this->assertSame( 'bad', $checks['locks']['state'] );
		$this->assertStringContainsString( 'Lost connection', $checks['locks']['detail'] );

		update_site_option(
			\SentinelShield\Lockdown\IntegrityScanner::REPORT_OPTION,
			array(
				'time'     => time(),
				'findings' => array(
					array(
						'severity' => 'critical',
						'id'       => 'x',
					),
				),
			)
		);
		$this->assertSame( 'bad', $by_id( $health->checks() )['findings']['state'] );
		delete_site_option( \SentinelShield\Lockdown\IntegrityScanner::REPORT_OPTION );
	}
}
