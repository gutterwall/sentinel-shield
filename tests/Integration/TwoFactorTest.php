<?php
/**
 * Two-factor authentication: setup, the second login step, email and backup
 * codes, limits, API logins, trusted browsers and resets.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Tests\Integration;

use SentinelShield\Plugin;
use SentinelShield\Repository\EventRepository;
use SentinelShield\Settings;
use SentinelShield\TwoFactor\SecretBox;
use SentinelShield\TwoFactor\Totp;
use SentinelShield\TwoFactor\TwoFactorLogin;
use SentinelShield\TwoFactor\UserTwoFactor;

/**
 * Thrown by the fake redirect so a test can see where the login was sent.
 */
final class RedirectedTo extends \RuntimeException {}

final class TwoFactorTest extends \WP_UnitTestCase {

	private int $now = 1800000000;

	private ?TwoFactorLogin $login = null;

	private UserTwoFactor $users;

	public static function tear_down_after_class(): void {
		Plugin::instance()->container()->get( TwoFactorLogin::class )->register();
		parent::tear_down_after_class();
	}

	public function set_up(): void {
		parent::set_up();
		self::unhook( Plugin::instance()->container()->get( TwoFactorLogin::class ) );
		global $wpdb;
		$wpdb->query( $wpdb->prepare( 'DELETE FROM %i', Plugin::instance()->container()->get( EventRepository::class )->table() ) );
		$this->users = Plugin::instance()->container()->get( UserTwoFactor::class );
		reset_phpmailer_instance();
		$_COOKIE = array();
	}

	public function tear_down(): void {
		if ( null !== $this->login ) {
			self::unhook( $this->login );
		}
		unset( $_SERVER['HTTP_ACCEPT'] );
		$_COOKIE = array();
		delete_site_option( Settings::OPTION );
		Plugin::instance()->container()->get( Settings::class )->refresh();
		parent::tear_down();
	}

	private static function unhook( TwoFactorLogin $login ): void {
		remove_filter( 'authenticate', array( $login, 'authenticate' ), 9999 );
		remove_action( 'login_form_' . TwoFactorLogin::ACTION, array( $login, 'screen' ) );
	}

	/**
	 * Saves settings and registers a login step with a fake clock and redirect.
	 *
	 * @param array<string, mixed> $twofa twofa.* settings.
	 */
	private function login_step( array $twofa = array() ): TwoFactorLogin {
		if ( null !== $this->login ) {
			self::unhook( $this->login );
		}
		update_site_option( Settings::OPTION, array( 'twofa' => $twofa ) );
		$c        = Plugin::instance()->container();
		$settings = $c->get( Settings::class );
		$settings->refresh();
		$this->login = new TwoFactorLogin(
			$settings,
			$this->users,
			$c->get( SecretBox::class ),
			$c->get( EventRepository::class ),
			static fn(): string => '198.51.100.20',
			static fn( string $url ): never => throw new RedirectedTo( $url ),
			fn(): int => $this->now
		);
		$this->login->register();
		return $this->login;
	}

	/**
	 * Creates a user with an authenticator app; returns [user, secret].
	 *
	 * @param string $role Role.
	 * @return array{0:\WP_User, 1:string}
	 */
	private function app_user( string $role = 'subscriber' ): array {
		$user   = get_userdata( self::factory()->user->create( array( 'user_pass' => 'right', 'role' => $role ) ) );
		$secret = $this->users->pending_secret( $user->ID );
		$this->assertTrue( $this->users->enable_totp( $user->ID, Totp::code( $secret, intdiv( $this->now, 30 ) - 5 ), $this->now - 150 ) );
		return array( $user, $secret );
	}

	private function code( string $secret, int $offset = 0 ): string {
		return Totp::code( $secret, intdiv( $this->now, 30 ) + $offset );
	}

	/**
	 * @return list<string>
	 */
	private function event_types(): array {
		return array_column( Plugin::instance()->container()->get( EventRepository::class )->query( array() )[0], 'event' );
	}

	public function test_setup_encrypts_the_secret_and_needs_a_valid_code(): void {
		$id      = self::factory()->user->create();
		$pending = $this->users->pending_secret( $id );
		$this->assertSame( $pending, $this->users->pending_secret( $id ), 'same QR code until renewed' );
		$this->assertFalse( $this->users->enable_totp( $id, '000000', $this->now ) );
		$this->assertFalse( $this->users->has_totp( $id ) );
		$this->assertTrue( $this->users->enable_totp( $id, Totp::code( $pending, intdiv( $this->now, 30 ) ), $this->now ) );
		$this->assertTrue( $this->users->has_totp( $id ) );
		$this->assertSame( $pending, $this->users->totp_secret( $id ) );
		$stored = (string) get_user_meta( $id, UserTwoFactor::META . 'totp', true );
		$this->assertStringStartsWith( 'sb1:', $stored );
		$this->assertStringNotContainsString( $pending, $stored );
		$this->assertSame( '', get_user_meta( $id, UserTwoFactor::META . 'totp_pending', true ) );
		$this->assertNotSame( $pending, $this->users->pending_secret( $id, true ) );
	}

	public function test_accounts_without_two_factor_pass_through(): void {
		$step = $this->login_step();
		$user = get_userdata( self::factory()->user->create( array( 'user_pass' => 'pw' ) ) );
		$this->assertFalse( $step->needs_second_step( $user ) );
		$this->assertInstanceOf( \WP_User::class, wp_authenticate( $user->user_login, 'pw' ) );
	}

	public function test_correct_password_goes_to_the_code_screen_without_a_login_cookie(): void {
		[ $user ] = $this->app_user();
		$this->login_step();
		$_REQUEST['redirect_to'] = 'http://example.org/wp-admin/edit.php';
		$_POST['rememberme']     = 'forever';
		try {
			wp_authenticate( $user->user_login, 'right' );
			$this->fail( 'expected a redirect' );
		} catch ( RedirectedTo $r ) {
			$this->assertStringContainsString( 'wp-login.php?action=sentinel_shield_2fa', $r->getMessage() );
		} finally {
			unset( $_REQUEST['redirect_to'], $_POST['rememberme'] );
		}
		$this->assertSame( 0, did_action( 'set_auth_cookie' ), 'no login cookie yet' );
		$pending = get_user_meta( $user->ID, UserTwoFactor::META . 'login', true );
		$this->assertSame( 'http://example.org/wp-admin/edit.php', $pending['redirect'] );
		$this->assertTrue( $pending['remember'] );
		$this->assertSame( $this->now + 600, $pending['expires'] );

		// A wrong password never reaches the second step.
		$this->assertWPError( wp_authenticate( $user->user_login, 'wrong' ) );
	}

	public function test_codes_tries_and_replay(): void {
		[ $user, $secret ] = $this->app_user();
		$step              = $this->login_step();
		$failed            = 0;
		add_action(
			'wp_login_failed',
			static function ( $name, $error ) use ( &$failed ): void {
				$failed += $error instanceof \WP_Error && TwoFactorLogin::ERROR_WRONG === $error->get_error_code() ? 1 : 0;
			},
			10,
			2
		);

		$token = $step->begin( $user );
		$this->assertSame( 'expired', $step->attempt( $user, str_repeat( 'a', 64 ), $this->code( $secret ) )['result'], 'wrong token' );
		$this->assertSame( 'ok', $step->attempt( $user, $token, $this->code( $secret ) )['result'] );
		$this->assertSame( 'expired', $step->attempt( $user, $token, $this->code( $secret ) )['result'], 'token is single-use' );

		$token = $step->begin( $user );
		$this->assertSame( 'wrong', $step->attempt( $user, $token, $this->code( $secret ) )['result'], 'a code works once' );
		$this->assertSame( 'ok', $step->attempt( $user, $token, $this->code( $secret, 1 ) )['result'], 'next step is fine' );

		$token = $step->begin( $user );
		for ( $i = 1; $i <= 4; $i++ ) {
			$this->assertSame( 'wrong', $step->attempt( $user, $token, '000000' )['result'] );
		}
		$this->assertSame( 'too_many', $step->attempt( $user, $token, '111111' )['result'] );
		$this->assertSame( 'expired', $step->attempt( $user, $token, $this->code( $secret, -1 ) )['result'], 'login cancelled' );
		$this->assertSame( 6, $failed, 'every wrong code counts as a failed login' );
		$this->assertContains( 'twofa_failed', $this->event_types() );

		$token      = $step->begin( $user );
		$this->now += 601;
		$this->assertSame( 'expired', $step->attempt( $user, $token, $this->code( $secret ) )['result'], 'ten minutes' );
	}

	public function test_backup_codes(): void {
		[ $user ] = $this->app_user();
		$step     = $this->login_step();
		$codes    = $this->users->new_backup_codes( $user->ID );
		$this->assertSame( 10, $this->users->backup_remaining( $user->ID ) );
		$this->assertSame( array( 'totp', 'backup' ), $step->methods( $user ) );
		$token  = $step->begin( $user );
		$result = $step->attempt( $user, $token, strtoupper( $codes[3] ) );
		$this->assertSame( array( 'ok', 'backup' ), array_values( $result ) );
		$this->assertSame( 9, $this->users->backup_remaining( $user->ID ) );
		$this->assertContains( 'twofa_backup_used', $this->event_types() );
		$token = $step->begin( $user );
		$this->assertSame( 'wrong', $step->attempt( $user, $token, $codes[3] )['result'], 'used up' );
		$this->assertStringNotContainsString( str_replace( '-', '', $codes[0] ), maybe_serialize( get_user_meta( $user->ID, UserTwoFactor::META . 'backup', true ) ), 'only hashes are stored' );

		// Backup codes alone do not turn two-factor on.
		$other = get_userdata( self::factory()->user->create() );
		$this->users->new_backup_codes( $other->ID );
		$this->assertFalse( $step->needs_second_step( $other ) );
	}

	public function test_required_accounts_without_an_app_get_email_codes(): void {
		$admin = get_userdata( self::factory()->user->create( array( 'role' => 'administrator', 'user_email' => 'boss@example.test' ) ) );
		$user  = get_userdata( self::factory()->user->create( array( 'role' => 'subscriber' ) ) );
		$step  = $this->login_step( array( 'required' => 'privileged' ) );
		reset_phpmailer_instance(); // Drops the "new administrator" alert.
		$this->assertTrue( $step->required( $admin ) );
		$this->assertFalse( $step->required( $user ) );
		$this->assertSame( array( 'email' ), $step->methods( $admin ) );
		$this->assertTrue( $step->setup_missing( $admin ) );
		$this->assertFalse( $step->needs_second_step( $user ) );

		$token = $step->begin( $admin );
		$mail  = tests_retrieve_phpmailer_instance()->get_sent();
		$this->assertSame( 'boss@example.test', $mail->to[0][0] );
		$this->assertMatchesRegularExpression( '/\b(\d{4}) (\d{4})\b/', $mail->body );
		$this->assertStringContainsString( '198.51.100.20', $mail->body );
		preg_match( '/\b(\d{4}) (\d{4})\b/', $mail->body, $m );
		$this->assertSame( 'wrong', $step->attempt( $admin, $token, '12345678' === $m[1] . $m[2] ? '87654321' : '12345678' )['result'] );
		$this->assertSame( array( 'ok', 'email' ), array_values( $step->attempt( $admin, $token, $m[1] . ' ' . $m[2] ) ) );

		// Resend limits: one a minute, five per login.
		$token = $step->begin( $admin );
		$this->assertWPError( $step->send_email_code( $admin, $token ), 'less than a minute' );
		for ( $i = 2; $i <= 5; $i++ ) {
			$this->now += 61;
			$this->assertTrue( $step->send_email_code( $admin, $token ) );
		}
		$this->now += 61;
		$this->assertWPError( $step->send_email_code( $admin, $token ), 'sixth code' );

		// Everyone; and email codes switched off.
		$this->login_step( array( 'required' => 'all' ) );
		$this->assertSame( array( 'email' ), $this->login->methods( $user ) );
		$this->login_step( array( 'required' => 'all', 'email' => false ) );
		$this->assertSame( array(), $this->login->methods( $user ) );
		$this->assertTrue( $this->login->needs_second_step( $user ), 'required accounts are never let in with the password alone' );
		$this->assertTrue( $this->login->locked_out( $user ) );
		$this->assertSame( TwoFactorLogin::ERROR_SETUP, $this->login->authenticate( $user )->get_error_code() );
		$this->assertTrue( $this->login->setup_missing( $user ) );
	}

	public function test_app_users_are_not_emailed_unless_they_chose_it(): void {
		[ $user, $secret ] = $this->app_user( 'administrator' );
		$step              = $this->login_step( array( 'required' => 'privileged' ) );
		reset_phpmailer_instance(); // Drops the "new administrator" alert.
		$this->assertSame( array( 'totp' ), $step->methods( $user ) );
		$this->assertFalse( $step->setup_missing( $user ) );
		$step->begin( $user );
		$this->assertFalse( tests_retrieve_phpmailer_instance()->get_sent(), 'no email when an app is set up' );
		$this->users->set_email( $user->ID, true );
		$this->assertSame( array( 'totp', 'email' ), $step->methods( $user ) );
		unset( $secret );
	}

	public function test_api_password_logins_are_refused_but_application_passwords_work(): void {
		[ $user ] = $this->app_user();
		$step     = $this->login_step();
		$_SERVER['HTTP_ACCEPT'] = 'application/json';
		$result                 = $step->authenticate( $user );
		$this->assertWPError( $result );
		$this->assertSame( TwoFactorLogin::ERROR_API, $result->get_error_code() );
		unset( $_SERVER['HTTP_ACCEPT'] );

		do_action( 'application_password_did_authenticate', $user, array() );
		$this->assertSame( $user, $step->authenticate( $user ), 'application password' );
	}

	public function test_trusted_browser(): void {
		[ $user ] = $this->app_user();
		$step     = $this->login_step( array( 'remember_days' => 30 ) );
		$name     = $step->trust_cookie_name( $user->ID );
		$this->assertMatchesRegularExpression( '/^sentinel_shield_2fa_trust_[0-9a-f]{16}$/', $name, 'the name does not reveal the user ID' );

		$_COOKIE[ $name ] = $step->trust_value( $user->ID, $this->now + DAY_IN_SECONDS );
		$this->assertSame( $user, $step->authenticate( $user ) );

		$_COOKIE[ $name ] = $step->trust_value( $user->ID, $this->now - 1 );
		$this->assertFalse( $step->trusted_browser( $user ), 'expired' );

		$_COOKIE[ $name ] = ( $this->now + 999 ) . '|' . substr( $step->trust_value( $user->ID, $this->now + DAY_IN_SECONDS ), -64 );
		$this->assertFalse( $step->trusted_browser( $user ), 'expiry cannot be changed' );

		$_COOKIE[ $name ] = $step->trust_value( $user->ID, $this->now + DAY_IN_SECONDS );
		$this->users->forget_devices( $user->ID );
		$this->assertFalse( $step->trusted_browser( $user ), 'forgotten' );

		$_COOKIE[ $name ] = $step->trust_value( $user->ID, $this->now + DAY_IN_SECONDS );
		$this->login_step( array( 'remember_days' => 0 ) );
		$this->assertFalse( $this->login->trusted_browser( $user ), 'feature off' );
	}

	public function test_unreadable_secret_never_falls_back_to_password_only(): void {
		[ $user ] = $this->app_user();
		$step     = $this->login_step();
		update_user_meta( $user->ID, UserTwoFactor::META . 'totp', 'sb1:' . base64_encode( random_bytes( 60 ) ) );
		$this->assertNull( $this->users->totp_secret( $user->ID ) );
		$this->assertSame( array(), $step->methods( $user ) );
		$this->assertTrue( $step->needs_second_step( $user ) );
		$result = $step->authenticate( $user );
		$this->assertWPError( $result, 'refused, with no code screen it could never pass' );
		$this->assertSame( TwoFactorLogin::ERROR_SETUP, $result->get_error_code() );

		// With backup codes left, the code screen is shown.
		$this->users->new_backup_codes( $user->ID );
		$this->expectException( RedirectedTo::class );
		$step->authenticate( $user );
	}

	public function test_reset_removes_everything(): void {
		[ $user ] = $this->app_user();
		$step     = $this->login_step( array( 'remember_days' => 30 ) );
		$this->users->set_email( $user->ID, true );
		$this->users->new_backup_codes( $user->ID );
		$step->begin( $user );
		$trust = $step->trust_value( $user->ID, $this->now + 999 );
		$this->users->reset( $user->ID );
		$this->assertSame( array( 'totp' => false, 'totp_readable' => false, 'email' => false, 'backup' => 0 ), $this->users->summary( $user->ID ) );
		$this->assertSame( '', get_user_meta( $user->ID, UserTwoFactor::META . 'login', true ) );
		$this->assertNotSame( $trust, $step->trust_value( $user->ID, $this->now + 999 ), 'trusted browsers forgotten' );
		$this->assertFalse( $step->needs_second_step( $user ) );
	}

	public function test_mask_email(): void {
		$this->assertSame( 'j***@example.com', TwoFactorLogin::mask_email( 'jo@example.com' ) );
		$this->assertSame( 'j*******@example.com', TwoFactorLogin::mask_email( 'jane.doe@example.com' ) );
		$this->assertSame( '***', TwoFactorLogin::mask_email( 'nonsense' ) );
	}
}
