<?php
/**
 * Work that lost its lock stops before its next state change.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Tests\Integration;

use SentinelShield\Audit\AuditExporter;
use SentinelShield\Plugin;
use SentinelShield\Repository\EventRepository;
use SentinelShield\Settings;
use SentinelShield\Support\Mutex;
use SentinelShield\Tests\Fakes\OtherWorker;

/**
 * Review 6 (lost-lock behavior): Mutex::renew() notices a named lock lost
 * with the database connection and a lock row taken over after its lease;
 * the audit export stops on it without moving the chain on, and the next
 * holder resends the same batch. The early firewall build, the file
 * integrity scan and Cloudflare sync are tested with their own suites.
 */
final class LostLockTest extends \WP_UnitTestCase {

	private ?OtherWorker $other = null;

	public function tear_down(): void {
		$this->other?->close();
		$this->other = null;
		foreach ( array( 'lost_test', 'audit_export' ) as $name ) {
			Mutex::release( $name );
		}
		// Mutex records each locking mode once per process; tests that forced
		// the lock row must not hide that record from later tests.
		( new \ReflectionProperty( Mutex::class, 'noted' ) )->setValue( null, array() );
		delete_site_option( AuditExporter::STATE );
		delete_site_option( Settings::OPTION );
		wp_clear_scheduled_hook( AuditExporter::CRON );
		Plugin::instance()->container()->get( Settings::class )->refresh();
		parent::tear_down();
	}

	private function other(): OtherWorker {
		$this->other ??= new OtherWorker();
		return $this->other;
	}

	public function test_a_held_named_lock_renews(): void {
		$this->assertTrue( Mutex::acquire( 'lost_test', 0 ) );
		$this->assertTrue( Mutex::renew( 'lost_test' ) );
		$this->assertTrue( Mutex::holds( 'lost_test' ) );
		$this->assertFalse( $this->other()->hold( 'lost_test' ), 'still ours' );
	}

	public function test_a_named_lock_lost_with_the_connection_is_noticed(): void {
		$this->assertTrue( Mutex::acquire( 'lost_test', 0 ) );
		$this->assertTrue( $this->other()->steal( 'lost_test' ), 'the connection dropped; another worker took the lock' );
		$this->assertFalse( Mutex::renew( 'lost_test' ) );
		$this->assertFalse( Mutex::holds( 'lost_test' ), 'forgotten' );
		Mutex::release( 'lost_test' );
		$this->assertTrue( $this->other()->holds( 'lost_test' ), 'releasing does not release the other worker\'s lock' );
	}

	public function test_a_named_lock_released_with_the_connection_is_noticed(): void {
		global $wpdb;
		$this->assertTrue( Mutex::acquire( 'lost_test', 0 ) );
		$wpdb->query( $wpdb->prepare( 'SELECT RELEASE_LOCK(%s)', OtherWorker::lock_name( 'lost_test' ) ) );
		$this->assertFalse( Mutex::renew( 'lost_test' ), 'free now, but no longer ours' );
	}

	public function test_a_lock_row_taken_over_is_noticed(): void {
		global $wpdb;
		$no_named = static fn( string $q ): string => str_contains( $q, 'GET_LOCK' ) ? 'SELECT NULL' : $q;
		add_filter( 'query', $no_named );
		try {
			$this->assertTrue( Mutex::acquire( 'lost_test', 0 ) );
			$this->assertTrue( Mutex::renew( 'lost_test' ), 'our row' );
			$key = '_' . OtherWorker::lock_name( 'lost_test' );
			// The lease ran out and another worker took the row over.
			$wpdb->query( $wpdb->prepare( 'UPDATE %i SET option_value = %s WHERE option_name = %s', $wpdb->base_prefix . 'options', ( time() + 60 ) . '|otherworker', $key ) );
			$this->assertFalse( Mutex::renew( 'lost_test' ) );
			$this->assertFalse( Mutex::holds( 'lost_test' ) );
			Mutex::release( 'lost_test' );
			$this->assertSame( ( time() + 60 ) . '|otherworker', (string) $wpdb->get_var( $wpdb->prepare( 'SELECT option_value FROM %i WHERE option_name = %s', $wpdb->base_prefix . 'options', $key ) ), 'the other worker\'s row stays' );
			$wpdb->query( $wpdb->prepare( 'DELETE FROM %i WHERE option_name = %s', $wpdb->base_prefix . 'options', $key ) );
		} finally {
			remove_filter( 'query', $no_named );
		}
	}

	public function test_audit_export_stops_on_a_lost_lock_and_the_next_holder_resends_the_batch(): void {
		update_site_option( Settings::OPTION, array( 'audit' => array( 'webhook_url' => 'https://audit.example.org/in' ) ) );
		$settings = Plugin::instance()->container()->get( Settings::class );
		$settings->refresh();
		$events = Plugin::instance()->container()->get( EventRepository::class );
		global $wpdb;
		$before = (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COALESCE(MAX(id), 0) FROM %i', $events->table() ) );
		for ( $i = 0; $i < 3; $i++ ) {
			$events->log(
				'lockout',
				array(
					'ip'     => '203.0.113.5',
					'module' => 'login',
					'reason' => 'test',
				)
			);
		}
		$first = (int) $wpdb->get_var( $wpdb->prepare( 'SELECT MIN(id) FROM %i WHERE id > %d', $events->table(), $before ) );
		update_site_option( AuditExporter::STATE, array( 'cursor' => $first - 1 ) );
		$sent  = array();
		$steal = false;
		$other = $this->other();
		$http  = static function ( string $url, array $args ) use ( &$sent, &$steal, $other ): array {
			$sent[] = json_decode( (string) $args['body'], true )['events'];
			if ( $steal ) {
				$other->steal( 'audit_export' ); // The worker's connection dropped while it waited.
			}
			return array(
				'headers'  => array(),
				'body'     => '',
				'response' => array(
					'code'    => 200,
					'message' => 'OK',
				),
				'cookies'  => array(),
				'filename' => null,
			);
		};
		$exporter = new AuditExporter( $settings, $events, $http );

		$steal = true;
		$exporter->run( 30.0 );
		$this->assertCount( 1, $sent );
		$this->assertSame( $first - 1, (int) AuditExporter::state()['cursor'], 'not recorded: the lock was lost before the state change' );
		$this->assertArrayNotHasKey( 'seq', AuditExporter::state(), 'the chain did not move on' );

		$exporter->run( 30.0 );
		$this->assertCount( 1, $sent, 'the other worker holds the lock: nothing sent' );

		$other->release( 'audit_export' );
		$steal = false;
		$exporter->run( 30.0 );
		$this->assertCount( 2, $sent );
		$this->assertSame( $sent[0], $sent[1], 'the same batch again, with the same sequence numbers and hashes' );
		$this->assertSame( $first + 2, (int) AuditExporter::state()['cursor'] );
		$this->assertSame( 3, (int) AuditExporter::state()['seq'] );
	}
}
