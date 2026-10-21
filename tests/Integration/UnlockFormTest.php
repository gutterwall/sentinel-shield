<?php
/**
 * The block page's unlock form: its token and what a submission does.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Tests\Integration;

use SentinelShield\Firewall\Gate;
use SentinelShield\Plugin;
use SentinelShield\Repository\EventRepository;
use SentinelShield\Repository\TokenRepository;
use SentinelShield\Settings;
use SentinelShield\Lockout\Unblocker;
use SentinelShield\Unlock\UnlockForm;
use SentinelShield\Unlock\UnlockService;

/**
 * Found by the required-coverage check (review 6): the unlock form token,
 * the form's CSRF and replay protection for blocked visitors, had no test.
 */
final class UnlockFormTest extends \WP_UnitTestCase {

	private const IP = '198.51.100.44';

	public function tear_down(): void {
		$_POST = array();
		delete_site_transient( 'sentinel_shield_unlock_rl_' . md5( self::IP ) );
		parent::tear_down();
	}

	public function test_the_token_is_bound_to_the_ip_and_the_hour(): void {
		$now   = intdiv( time(), HOUR_IN_SECONDS );
		$token = UnlockForm::token( self::IP );
		$this->assertSame( 64, strlen( $token ) );
		$this->assertTrue( UnlockForm::verify( $token, self::IP ) );
		$this->assertTrue( UnlockForm::verify( UnlockForm::token( self::IP, $now - 1 ), self::IP ), 'a page loaded in the previous hour still works' );
		$this->assertFalse( UnlockForm::verify( UnlockForm::token( self::IP, $now - 2 ), self::IP ), 'older pages do not' );
		$this->assertFalse( UnlockForm::verify( UnlockForm::token( self::IP, $now + 1 ), self::IP ) );
		$this->assertFalse( UnlockForm::verify( $token, '198.51.100.45' ), 'another visitor cannot use it' );
		$this->assertFalse( UnlockForm::verify( '', self::IP ) );
		$this->assertFalse( UnlockForm::verify( substr( $token, 0, -1 ) . ( '0' === substr( $token, -1 ) ? '1' : '0' ), self::IP ) );
	}

	/**
	 * Submits the form; returns the notice and how many unlock links exist.
	 *
	 * @param array<string, string> $post Form fields.
	 * @return array{0:string, 1:int}
	 */
	private function submit( array $post ): array {
		$c       = Plugin::instance()->container();
		$service = new UnlockService( $c->get( Settings::class ), $c->get( TokenRepository::class ), $c->get( Unblocker::class ), $c->get( EventRepository::class ), $c->get( Gate::class ), static fn(): string => self::IP );
		$_POST   = $post + array( 'sentinel_unlock_request' => '1' );
		$notice  = ( new \ReflectionMethod( UnlockService::class, 'handle_request' ) )->invoke( $service );
		global $wpdb;
		return array( (string) $notice, (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM %i', $c->get( TokenRepository::class )->table() ) ) );
	}

	public function test_a_submission_needs_a_valid_token_and_counts_only_then(): void {
		$admin = self::factory()->user->create( array( 'role' => 'administrator' ) );
		if ( is_multisite() ) {
			grant_super_admin( $admin );
		}
		$email = get_userdata( $admin )->user_email;
		[ , $links ] = $this->submit( array() );

		[ $notice, $after ] = $this->submit(
			array(
				'sentinel_email' => $email,
				'sentinel_token' => UnlockForm::token( '198.51.100.45' ),
			)
		);
		$this->assertStringContainsString( 'form expired', $notice, 'a token for another IP' );
		$this->assertSame( $links, $after, 'no link created' );
		$this->assertFalse( get_site_transient( 'sentinel_shield_unlock_rl_' . md5( self::IP ) ), 'and the rate limit is not used up by forged posts' );

		[ $notice, $after ] = $this->submit(
			array(
				'sentinel_email'   => $email,
				'sentinel_token'   => UnlockForm::token( self::IP ),
				'sentinel_website' => 'http://spam.example',
			)
		);
		$this->assertStringContainsString( 'If that address belongs', $notice, 'a bot filling the hidden field gets the usual answer' );
		$this->assertSame( $links, $after, 'but no link' );

		[ $notice, $after ] = $this->submit(
			array(
				'sentinel_email' => $email,
				'sentinel_token' => UnlockForm::token( self::IP ),
			)
		);
		$this->assertStringContainsString( 'If that address belongs', $notice, 'the same answer whether or not the address is an admin' );
		$this->assertSame( $links + 1, $after, 'a link for the administrator' );
	}
}
