<?php
/**
 * Automatic administrator allowlist entries expire unless they are used.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Tests\Integration;

use SentinelShield\Firewall\Gate;
use SentinelShield\Firewall\RuleCache;
use SentinelShield\Install\Schema;
use SentinelShield\Net\Cidr;
use SentinelShield\Plugin;
use SentinelShield\Repository\BlockRepository;
use SentinelShield\Safety\AdminProtection;
use SentinelShield\Support\Throttle;

final class AdminAllowlistTest extends \WP_UnitTestCase {

	private BlockRepository $repo;

	private AdminProtection $protection;

	public function set_up(): void {
		parent::set_up();
		$c                = Plugin::instance()->container();
		$this->repo       = $c->get( BlockRepository::class );
		$this->protection = $c->get( AdminProtection::class );
		global $wpdb;
		$wpdb->query( $wpdb->prepare( 'DELETE FROM %i', $this->repo->table() ) );
		$c->get( RuleCache::class )->flush();
		$prop = new \ReflectionProperty( Throttle::class, 'seen' );
		$prop->setAccessible( true );
		$prop->setValue( null, array() );
	}

	/**
	 * Expiry of the exact allow entry for an IP (Unix time), null when permanent.
	 *
	 * @param string $ip IP.
	 */
	private function expiry( string $ip ): ?int {
		$row = $this->repo->find_exact( 'allow', Cidr::parse( $ip ) );
		$this->assertNotNull( $row );
		return null === $row['expires_at'] ? null : (int) strtotime( $row['expires_at'] . ' UTC' );
	}

	private function set_expiry( string $ip, ?int $at ): void {
		global $wpdb;
		$wpdb->query( $wpdb->prepare( 'UPDATE %i SET expires_at = %s WHERE label = %s', $this->repo->table(), null === $at ? '' : gmdate( 'Y-m-d H:i:s', $at ), $ip ) );
		if ( null === $at ) {
			$wpdb->query( $wpdb->prepare( 'UPDATE %i SET expires_at = NULL WHERE label = %s', $this->repo->table(), $ip ) );
		}
		Plugin::instance()->container()->get( RuleCache::class )->flush();
	}

	public function test_new_entries_expire_and_are_renewed_while_used(): void {
		$this->assertTrue( $this->protection->ensure_allowlisted( '203.0.113.10', 1, 30 ) );
		$this->assertEqualsWithDelta( time() + 30 * DAY_IN_SECONDS, $this->expiry( '203.0.113.10' ), 5 );
		$this->assertFalse( $this->protection->ensure_allowlisted( '203.0.113.10', 1, 30 ), 'already there' );

		// Used again after 25 days: pushed back to 30 days from now.
		$this->set_expiry( '203.0.113.10', time() + 5 * DAY_IN_SECONDS );
		$this->assertTrue( $this->protection->renew( '203.0.113.10', 30 ) );
		$this->assertEqualsWithDelta( time() + 30 * DAY_IN_SECONDS, $this->expiry( '203.0.113.10' ), 5 );

		// At most one write per IP per day from dashboard use.
		$this->set_expiry( '203.0.113.10', time() + 5 * DAY_IN_SECONDS );
		$this->assertFalse( $this->protection->renew( '203.0.113.10', 30 ) );
		$this->assertEqualsWithDelta( time() + 5 * DAY_IN_SECONDS, $this->expiry( '203.0.113.10' ), 5 );

		// Saving settings always renews.
		$this->assertFalse( $this->protection->ensure_allowlisted( '203.0.113.10', 1, 30 ) );
		$this->assertEqualsWithDelta( time() + 30 * DAY_IN_SECONDS, $this->expiry( '203.0.113.10' ), 5 );
	}

	public function test_unused_entries_stop_allowing(): void {
		$gate = Plugin::instance()->container()->get( Gate::class );
		$this->repo->add( 'block', Cidr::parse( '203.0.113.0/24' ), 'test block', 'manual' );
		$this->protection->ensure_allowlisted( '203.0.113.11', 1, 30 );
		Plugin::instance()->container()->get( RuleCache::class )->flush();
		$this->assertSame( 'allowlist', $gate->evaluate( '203.0.113.11', '/', false, true )->reason );

		$this->set_expiry( '203.0.113.11', time() - 60 );
		$this->assertTrue( $gate->evaluate( '203.0.113.11', '/', false, true )->is_block(), 'expired: no longer trusted' );
	}

	public function test_manual_entries_are_never_changed_and_zero_days_means_permanent(): void {
		$this->repo->add( 'allow', Cidr::parse( '203.0.113.12' ), 'office', 'manual', time() + DAY_IN_SECONDS );
		$this->assertFalse( $this->protection->renew( '203.0.113.12', 30, true ) );
		$this->assertEqualsWithDelta( time() + DAY_IN_SECONDS, $this->expiry( '203.0.113.12' ), 5 );
		$this->assertFalse( $this->protection->ensure_allowlisted( '203.0.113.12', 1, 30 ), 'covered by the manual entry' );
		$this->assertSame( 'manual', $this->repo->find_exact( 'allow', Cidr::parse( '203.0.113.12' ) )['source'] );

		$this->assertTrue( $this->protection->ensure_allowlisted( '203.0.113.13', 1, 0 ) );
		$this->assertNull( $this->expiry( '203.0.113.13' ) );

		$this->protection->ensure_allowlisted( '203.0.113.14', 1, 30 );
		$this->protection->ensure_allowlisted( '203.0.113.14', 1, 0 );
		$this->assertNull( $this->expiry( '203.0.113.14' ), 'switching expiry off makes existing entries permanent' );
	}

	public function test_upgrade_gives_old_permanent_entries_an_expiry(): void {
		$this->repo->add( 'allow', Cidr::parse( '203.0.113.15' ), 'old auto entry', 'admin_auto' );
		$this->repo->add( 'allow', Cidr::parse( '203.0.113.16' ), 'manual permanent', 'manual' );
		update_site_option( Schema::OPTION, 3 );
		Schema::install();
		$this->assertSame( Schema::VERSION, (int) get_site_option( Schema::OPTION ) );
		$this->assertEqualsWithDelta( time() + 30 * DAY_IN_SECONDS, $this->expiry( '203.0.113.15' ), 5 );
		$this->assertNull( $this->expiry( '203.0.113.16' ) );
	}
}
