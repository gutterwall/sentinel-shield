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

	use AdminUsers;

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
			// A closure, not an arrow function: PHP 8.1 rejects arrow functions returning never.
			static function ( string $url ): never {
				throw new RedirectedTo( $url );
			},
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
		$pending = array_values( (array) get_user_meta( $user->ID, UserTwoFactor::META . 'login', true ) )[0];
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
		$admin = self::create_admin_user( array( 'user_email' => 'boss@example.test' ) );
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

		// Resend limits are per account, whichever login asks: one a minute, EMAILS_PER_HOUR an hour.
		$this->now += 61;
		$token = $step->begin( $admin );
		$this->assertCount( 2, tests_retrieve_phpmailer_instance()->mock_sent );
		$this->assertWPError( $step->send_email_code( $admin, $token ), 'less than a minute' );
		for ( $i = 3; $i <= TwoFactorLogin::EMAILS_PER_HOUR; $i++ ) {
			$this->now += 61;
			$this->assertTrue( $step->send_email_code( $admin, $token ) );
		}
		$this->now += 61;
		$this->assertWPError( $step->send_email_code( $admin, $token ), 'hourly budget used up' );
		// Starting a new login does not reset it.
		$this->now += 61;
		$fresh = $step->begin( $admin );
		$this->assertIsString( $fresh );
		$this->assertCount( TwoFactorLogin::EMAILS_PER_HOUR, tests_retrieve_phpmailer_instance()->mock_sent, 'no extra email' );
		$this->assertWPError( $step->send_email_code( $admin, $fresh ) );
		$this->assertNotNull( $step->pending( $admin->ID, $token ), 'the earlier login is still pending' );

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
		$until  = $this->now + DAY_IN_SECONDS;
		$laptop = $this->users->add_device( $user->ID, $until, 'Mozilla/5.0 (Windows NT 10.0) Firefox/140.0', '198.51.100.20', $this->now );
		$phone  = $this->users->add_device( $user->ID, $until, 'Mozilla/5.0 (iPhone) Safari/605.1', '198.51.100.21', $this->now );

		$_COOKIE[ $name ] = $step->trust_value( $user->ID, $laptop, $until );
		$this->assertSame( $user, $step->authenticate( $user ) );

		$_COOKIE[ $name ] = $step->trust_value( $user->ID, $laptop, $this->now - 1 );
		$this->assertFalse( $step->trusted_browser( $user ), 'expired' );

		$_COOKIE[ $name ] = $laptop . '|' . ( $this->now + 999 ) . '|' . substr( $step->trust_value( $user->ID, $laptop, $until ), -64 );
		$this->assertFalse( $step->trusted_browser( $user ), 'expiry cannot be changed' );

		$_COOKIE[ $name ] = $step->trust_value( $user->ID, str_repeat( 'a', 24 ), $until );
		$this->assertFalse( $step->trusted_browser( $user ), 'a correctly signed but unregistered browser is not trusted' );

		// Revoking one browser leaves the others.
		$this->assertTrue( $this->users->forget_device( $user->ID, $laptop ) );
		$_COOKIE[ $name ] = $step->trust_value( $user->ID, $laptop, $until );
		$this->assertFalse( $step->trusted_browser( $user ), 'revoked' );
		$_COOKIE[ $name ] = $step->trust_value( $user->ID, $phone, $until );
		$this->assertTrue( $step->trusted_browser( $user ) );

		$this->users->forget_devices( $user->ID );
		$this->assertFalse( $step->trusted_browser( $user ), 'all forgotten' );

		$phone            = $this->users->add_device( $user->ID, $until, 'x', '198.51.100.21', $this->now );
		$_COOKIE[ $name ] = $step->trust_value( $user->ID, $phone, $until );
		$this->login_step( array( 'remember_days' => 0 ) );
		$this->assertFalse( $this->login->trusted_browser( $user ), 'feature off' );
	}

	/**
	 * Review finding 4: a password change or reset, or a new authenticator,
	 * ends trust in every browser and every pending code screen.
	 */
	public function test_credential_changes_revoke_trusted_browsers_and_pending_logins(): void {
		[ $user ] = $this->app_user();
		$step     = $this->login_step( array( 'remember_days' => 30 ) );
		$name     = $step->trust_cookie_name( $user->ID );
		$until    = $this->now + DAY_IN_SECONDS;
		$trust    = function () use ( $user, $step, $name, $until ): void {
			$device           = $this->users->add_device( $user->ID, $until, 'x', '198.51.100.20', $this->now );
			$_COOKIE[ $name ] = $step->trust_value( $user->ID, $device, $until );
			$this->assertTrue( $step->trusted_browser( $user ) );
		};

		$trust();
		$token = $step->begin( $user );
		wp_set_password( 'new-password-1', $user->ID );
		$this->assertFalse( $step->trusted_browser( $user ), 'wp_set_password' );
		$this->assertNull( $step->pending( $user->ID, $token ), 'pending code screen ended' );
		$this->assertContains( 'twofa_devices_revoked', $this->event_types() );

		$trust();
		wp_update_user(
			array(
				'ID'        => $user->ID,
				'user_pass' => 'new-password-2',
			)
		);
		$this->assertFalse( $step->trusted_browser( $user ), 'profile password change' );

		$trust();
		do_action( 'after_password_reset', get_userdata( $user->ID ), 'x' );
		$this->assertFalse( $step->trusted_browser( $user ), 'password reset' );

		$trust();
		wp_update_user(
			array(
				'ID'           => $user->ID,
				'display_name' => 'Renamed',
			)
		);
		$this->assertTrue( $step->trusted_browser( $user ), 'other profile changes keep trust' );

		$secret = $this->users->pending_secret( $user->ID, true );
		$this->assertTrue( $this->users->enable_totp( $user->ID, Totp::code( $secret, intdiv( $this->now, 30 ) ), $this->now ) );
		$this->assertFalse( $step->trusted_browser( $user ), 'replaced authenticator' );
	}

	/**
	 * Review finding 5: logins live side by side, and the budgets are per account.
	 */
	public function test_restarting_the_login_cannot_reset_limits_or_cancel_others(): void {
		[ $user, $secret ] = $this->app_user();
		$step              = $this->login_step();
		$first             = $step->begin( $user );
		$second            = $step->begin( $user );
		$this->assertNotNull( $step->pending( $user->ID, $first ), 'a new login does not cancel the first' );
		$this->assertNotNull( $step->pending( $user->ID, $second ) );

		// Wrong codes count across logins.
		$wrong = '000000' === $this->code( $secret ) ? '111111' : '000000';
		for ( $i = 0; $i < 4; $i++ ) {
			$this->assertSame( 'wrong', $step->attempt( $user, $first, $wrong )['result'] );
		}
		$third = $step->begin( $user );
		$this->assertSame( 'wrong', $step->attempt( $user, $third, $wrong )['result'], 'a fresh login has its own five tries' );

		// ...but not past the hourly account budget.
		$tokens = array( $third );
		$wrongs = 5;
		while ( $wrongs < TwoFactorLogin::WRONG_PER_HOUR ) {
			$token = end( $tokens );
			$out   = $step->attempt( $user, $token, $wrong )['result'];
			++$wrongs;
			if ( 'too_many' === $out || null === $step->pending( $user->ID, $token ) ) {
				$tokens[] = $step->begin( $user );
			}
		}
		$blocked = $step->begin( $user );
		$this->assertWPError( $blocked, 'no new logins after too many wrong codes' );
		$this->assertSame( TwoFactorLogin::ERROR_LIMIT, $blocked->get_error_code() );

		// A day later everything works again, and a correct code ends all pending logins.
		$this->now += DAY_IN_SECONDS;
		$a = $step->begin( $user );
		$b = $step->begin( $user );
		$this->assertSame( 'ok', $step->attempt( $user, $b, $this->code( $secret ) )['result'] );
		$this->assertNull( $step->pending( $user->ID, $a ) );

		// At most CHALLENGES_PER_HOUR new logins an hour.
		$this->now += DAY_IN_SECONDS;
		for ( $i = 0; $i < TwoFactorLogin::CHALLENGES_PER_HOUR; $i++ ) {
			$this->assertIsString( $step->begin( $user ) );
		}
		$this->assertWPError( $step->begin( $user ) );
		$this->assertLessThanOrEqual( TwoFactorLogin::MAX_CHALLENGES, count( (array) get_user_meta( $user->ID, UserTwoFactor::META . 'login', true ) ) );
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
		$trust = $step->trust_value( $user->ID, 'device', $this->now + 999 );
		$this->users->reset( $user->ID );
		$this->assertSame( array( 'totp' => false, 'totp_readable' => false, 'email' => false, 'backup' => 0 ), $this->users->summary( $user->ID ) );
		$this->assertSame( '', get_user_meta( $user->ID, UserTwoFactor::META . 'login', true ) );
		$this->assertNotSame( $trust, $step->trust_value( $user->ID, 'device', $this->now + 999 ), 'trusted browsers forgotten' );
		$this->assertFalse( $step->needs_second_step( $user ) );
	}

	public function test_mask_email(): void {
		$this->assertSame( 'j***@example.com', TwoFactorLogin::mask_email( 'jo@example.com' ) );
		$this->assertSame( 'j*******@example.com', TwoFactorLogin::mask_email( 'jane.doe@example.com' ) );
		$this->assertSame( '***', TwoFactorLogin::mask_email( 'nonsense' ) );
	}
}
