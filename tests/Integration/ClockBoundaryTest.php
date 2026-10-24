<?php
/**
 * Every expiry and time window at its exact boundary.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Tests\Integration;

use SentinelShield\Firewall\Gate;
use SentinelShield\Firewall\RuleCache;
use SentinelShield\Net\Cidr;
use SentinelShield\Plugin;
use SentinelShield\Repository\BlockRepository;
use SentinelShield\Repository\TokenRepository;
use SentinelShield\Support\Mutex;
use SentinelShield\TwoFactor\Totp;
use SentinelShield\TwoFactor\UserTwoFactor;

/**
 * Review 5 (P1): authenticator codes, rule expiry, unlock links, trusted
 * browsers, identity confirmations and lock leases each end exactly where
 * they should: valid up to the boundary, invalid from it on, and a clock
 * that is a step ahead or behind is tolerated only as documented.
 */
final class ClockBoundaryTest extends \WP_UnitTestCase {

	/**
	 * Authenticator codes: one 30-second step of drift either way, no more,
	 * at the exact edges of the steps; a used step never comes back.
	 */
	public function test_authenticator_code_windows(): void {
		$secret = Totp::generate_secret();
		$t      = 1800000000; // A step boundary (divisible by 30).
		$this->assertSame( 0, $t % 30 );
		$step   = intdiv( $t, 30 );
		foreach ( array( -1, 0, 1 ) as $drift ) {
			$code = Totp::code( $secret, $step + $drift );
			$this->assertSame( $step + $drift, Totp::verify( $secret, $code, $t ), "a phone clock $drift step(s) off" );
			$this->assertSame( $step + $drift, Totp::verify( $secret, $code, $t + 29 ), "the same, at the end of the step ($drift)" );
		}
		$this->assertNull( Totp::verify( $secret, Totp::code( $secret, $step - 2 ), $t ), 'two steps behind' );
		$this->assertNull( Totp::verify( $secret, Totp::code( $secret, $step + 2 ), $t ), 'two steps ahead' );
		// At the last second of a step the next step's code is accepted; one second later the old previous one is not.
		$this->assertNotNull( Totp::verify( $secret, Totp::code( $secret, $step - 1 ), $t + 29 ) );
		$this->assertNull( Totp::verify( $secret, Totp::code( $secret, $step - 1 ), $t + 30 ) );
		// Replay protection by step.
		$this->assertNull( Totp::verify( $secret, Totp::code( $secret, $step ), $t, $step ), 'the step already used' );
		$this->assertNull( Totp::verify( $secret, Totp::code( $secret, $step - 1 ), $t, $step ), 'an earlier step after a later one' );
		$this->assertSame( $step + 1, Totp::verify( $secret, Totp::code( $secret, $step + 1 ), $t, $step ) );
	}

	/**
	 * A rule ending now no longer blocks; one ending a second later still does.
	 */
	public function test_rule_expiry_at_the_second(): void {
		global $wpdb;
		$c     = Plugin::instance()->container();
		$repo  = $c->get( BlockRepository::class );
		$cache = $c->get( RuleCache::class );
		$gate  = $c->get( Gate::class );
		$wpdb->query( $wpdb->prepare( 'DELETE FROM %i', $repo->table() ) );
		$id    = $repo->add( 'block', Cidr::parse( '203.0.113.77' ), 'clock', 'manual', time() + 3600 );
		$set   = static function ( int $at ) use ( $wpdb, $repo, $id, $cache ): void {
			$wpdb->update( $repo->table(), array( 'expires_at' => gmdate( 'Y-m-d H:i:s', $at ) ), array( 'id' => $id ) );
			$cache->flush();
		};
		$now = time();
		$set( $now + 2 );
		$this->assertTrue( $gate->evaluate( '203.0.113.77', '/', false, true )->is_block(), 'ends in two seconds: still blocks' );
		$set( $now );
		$this->assertFalse( $gate->evaluate( '203.0.113.77', '/', false, true )->is_block(), 'ends now: no longer blocks' );
		$this->assertSame( array(), $repo->find_containing( 'block', (string) inet_pton( '203.0.113.77' ) ) );
		$this->assertSame( 1, $repo->purge_expired(), 'and is purged' );
		$cache->flush();
	}

	/**
	 * Unlock links, trusted browsers and identity confirmations end exactly
	 * at their expiry.
	 */
	public function test_link_device_and_confirmation_expiry(): void {
		global $wpdb;
		$tokens = Plugin::instance()->container()->get( TokenRepository::class );
		$token  = $tokens->create( 1, '203.0.113.30', 600 );
		$wpdb->query( $wpdb->prepare( 'UPDATE %i SET expires_at = %s', $tokens->table(), gmdate( 'Y-m-d H:i:s', time() + 2 ) ) );
		$this->assertNotNull( $tokens->peek( $token ), 'two seconds left' );
		$wpdb->query( $wpdb->prepare( 'UPDATE %i SET expires_at = %s', $tokens->table(), gmdate( 'Y-m-d H:i:s', time() ) ) );
		$this->assertNull( $tokens->peek( $token ), 'expires now' );

		$users  = Plugin::instance()->container()->get( UserTwoFactor::class );
		$id     = self::factory()->user->create();
		$t      = 1800000000;
		$device = $users->add_device( $id, $t + 100, 'Browser', '198.51.100.1', $t );
		$this->assertArrayHasKey( $device, $users->devices( $id, $t + 99 ) );
		$this->assertArrayNotHasKey( $device, $users->devices( $id, $t + 100 ), 'trusted browser expires at its time' );

		$users->confirm( $id, 'session', $t );
		$this->assertTrue( $users->recently_confirmed( $id, 'session', $t + UserTwoFactor::REAUTH_TTL - 1 ) );
		$this->assertFalse( $users->recently_confirmed( $id, 'session', $t + UserTwoFactor::REAUTH_TTL ), 'the confirmation ends after exactly its TTL' );
	}

	/**
	 * A fallback lock row is held until its lease ends, and can be taken over
	 * only after that (the database's named locks have no lease to test).
	 */
	public function test_lock_row_lease_boundary(): void {
		global $wpdb;
		$row  = new \ReflectionMethod( Mutex::class, 'acquire_row' );
		$name = new \ReflectionMethod( Mutex::class, 'db_name' );
		$key = '_' . $name->invoke( null, 'clock_test' );
		try {
			$wpdb->insert(
				$wpdb->base_prefix . 'options',
				array(
					'option_name'  => $key,
					'option_value' => time() . '|someone-else',
					'autoload'     => 'no',
				)
			);
			$this->assertFalse( $row->invoke( null, 'clock_test', 0 ), 'the lease ends this second: still held' );
			$wpdb->update( $wpdb->base_prefix . 'options', array( 'option_value' => ( time() - 1 ) . '|someone-else' ), array( 'option_name' => $key ) );
			$this->assertTrue( $row->invoke( null, 'clock_test', 0 ), 'ended a second ago: taken over' );
			Mutex::release( 'clock_test' );
			$this->assertNull( $wpdb->get_var( $wpdb->prepare( 'SELECT option_value FROM %i WHERE option_name = %s', $wpdb->base_prefix . 'options', $key ) ), 'released' );
		} finally {
			$wpdb->delete( $wpdb->base_prefix . 'options', array( 'option_name' => $key ) );
			// Recorded once per process: let later tests record the mode again.
			( new \ReflectionProperty( Mutex::class, 'noted' ) )->setValue( null, array() );
		}
	}
}
