<?php
/**
 * Storage stays within its budgets during a sustained attack.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Tests\Integration;

use SentinelShield\Audit\AuditExporter;
use SentinelShield\Login\BruteForceGuard;
use SentinelShield\Modules\MaintenanceModule;
use SentinelShield\Plugin;
use SentinelShield\Repository\EventRepository;
use SentinelShield\Repository\LoginAttemptRepository;
use SentinelShield\Settings;

/**
 * Review 5 (storage budgets): the event log, the waiting audit backlog and
 * the login history are capped by settings, the hourly housekeeping keeps to
 * its time budget, and none of it erases what the limits enforce with.
 */
final class StorageBudgetTest extends \WP_UnitTestCase {

	public function set_up(): void {
		parent::set_up();
		global $wpdb;
		$c = Plugin::instance()->container();
		$wpdb->query( $wpdb->prepare( 'DELETE FROM %i', $c->get( EventRepository::class )->table() ) );
		$wpdb->query( $wpdb->prepare( 'DELETE FROM %i', $c->get( LoginAttemptRepository::class )->table() ) );
		$wpdb->query( $wpdb->prepare( 'DELETE FROM %i', $c->get( LoginAttemptRepository::class )->counters_table() ) );
		add_filter( 'pre_http_request', array( self::class, 'unreachable' ) );
	}

	public function tear_down(): void {
		remove_filter( 'pre_http_request', array( self::class, 'unreachable' ) );
		foreach ( array( Settings::OPTION, AuditExporter::STATE, MaintenanceModule::REPORT ) as $option ) {
			delete_site_option( $option );
		}
		wp_clear_scheduled_hook( 'sentinel_shield_maintenance', array( 'more' ) );
		Plugin::instance()->container()->get( Settings::class )->refresh();
		parent::tear_down();
	}

	/**
	 * The audit endpoint is down for the whole attack.
	 */
	public static function unreachable(): \WP_Error {
		return new \WP_Error( 'http_request_failed', 'down' );
	}

	/**
	 * @param array<string, mixed> $settings Settings.
	 */
	private static function settings( array $settings ): void {
		update_site_option( Settings::OPTION, $settings );
		Plugin::instance()->container()->get( Settings::class )->refresh();
	}

	/**
	 * Fast bulk insert of blocked-request events, $minutes_ago old.
	 */
	private static function events( int $n, int $minutes_ago = 1 ): void {
		global $wpdb;
		$table = Plugin::instance()->container()->get( EventRepository::class )->table();
		$at    = gmdate( 'Y-m-d H:i:s', time() - $minutes_ago * MINUTE_IN_SECONDS );
		for ( $done = 0; $done < $n; $done += 1000 ) {
			$rows = array();
			for ( $i = 0; $i < min( 1000, $n - $done ); $i++ ) {
				$rows[] = $wpdb->prepare( '(%s, %s, %s, %s, %s)', $at, '203.0.113.' . ( $i % 250 ), 'blocked', 'ip_gate', 'attack' );
			}
			$wpdb->query( "INSERT INTO $table (created_at, ip_text, event, module, reason) VALUES " . implode( ',', $rows ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery -- Prepared rows.
		}
	}

	private static function rows( string $table ): int {
		global $wpdb;
		return (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM %i', $table ) );
	}

	public function test_the_event_log_is_capped(): void {
		self::settings( array( 'general' => array( 'event_max_rows' => 10000 ) ) );
		self::events( 25000 );
		$result = MaintenanceModule::run( Plugin::instance()->container() );
		$this->assertSame( 15000, $result['events'] );
		$this->assertSame( 10000, self::rows( Plugin::instance()->container()->get( EventRepository::class )->table() ), 'the newest 10000 are kept' );
		$this->assertSame( 0, $result['unfinished'] );
		$this->assertSame( $result['events'], get_site_option( MaintenanceModule::REPORT )['events'], 'the run is reported' );
	}

	public function test_the_waiting_audit_backlog_has_its_own_cap_and_the_gap_is_counted(): void {
		self::settings(
			array(
				'general' => array( 'event_max_rows' => 10000 ),
				'audit'   => array(
					'webhook_url'     => 'https://audit.example.org/in',
					'max_unsent_rows' => 3000,
				),
			)
		);
		self::events( 6000 );
		global $wpdb;
		$table = Plugin::instance()->container()->get( EventRepository::class )->table();
		$first = (int) $wpdb->get_var( $wpdb->prepare( 'SELECT MIN(id) FROM %i', $table ) );
		// Delivered up to the first 1000; then the endpoint went down.
		update_site_option( AuditExporter::STATE, array( 'cursor' => $first + 999 ) );
		self::events( 8000 );
		MaintenanceModule::run( Plugin::instance()->container() );
		$cursor  = $first + 999;
		$waiting = (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM %i WHERE id > %d', $table, $cursor ) );
		$sent    = (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM %i WHERE id <= %d', $table, $cursor ) );
		$this->assertSame( 3000, $waiting, 'the waiting events are capped at 3000' );
		$this->assertSame( 0, $sent, 'delivered events beyond the log cap are pruned first' );
		$this->assertSame( 13000 - 3000, (int) AuditExporter::state()['dropped'], 'the undelivered events pruned are counted as a gap' );
	}

	public function test_the_login_history_is_capped_without_weakening_the_limits(): void {
		self::settings( array( 'login' => array( 'history_max_rows' => 10000, 'max_failures' => 5, 'window_minutes' => 15 ) ) );
		$c     = Plugin::instance()->container();
		$repo  = $c->get( LoginAttemptRepository::class );
		$guard = $c->get( BruteForceGuard::class );
		// A long distributed attack: 30000 failures over the last two days...
		global $wpdb;
		for ( $done = 0; $done < 30000; $done += 1000 ) {
			$rows = array();
			for ( $i = 0; $i < 1000; $i++ ) {
				$rows[] = $wpdb->prepare( '(UNHEX(%s), %s, %s)', bin2hex( (string) inet_pton( '10.' . ( $i % 200 ) . '.0.' . intdiv( $done, 1000 ) ) ), 'admin', gmdate( 'Y-m-d H:i:s', time() - DAY_IN_SECONDS - ( $done + $i ) ) );
			}
			$wpdb->query( "INSERT INTO {$repo->table()} (ip, account, created_at) VALUES " . implode( ',', $rows ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery -- Prepared rows.
		}
		// ...and one IP failing right now, five times.
		for ( $i = 0; $i < 5; $i++ ) {
			$repo->record( (string) inet_pton( '198.51.100.99' ), 'victim', time() - $i );
		}
		$this->assertFalse( $guard->check( '198.51.100.99', 'victim' )['allowed'], 'locked by the limit' );
		MaintenanceModule::run( $c );
		$this->assertLessThanOrEqual( 10000, self::rows( $repo->table() ) );
		$this->assertSame( 5, $repo->count_ip( (string) inet_pton( '198.51.100.99' ), time() - 15 * MINUTE_IN_SECONDS ), 'the counters the limit uses are intact' );
		$this->assertFalse( $guard->check( '198.51.100.99', 'victim' )['allowed'], 'still locked after the pruning' );
		$recent = (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM %i WHERE created_at >= %s', $repo->table(), gmdate( 'Y-m-d H:i:s', time() - 15 * MINUTE_IN_SECONDS ) ) );
		$this->assertSame( 5, $recent, 'attempts inside the counting window are never pruned' );
	}

	public function test_a_run_out_of_time_still_progresses_and_continues_soon(): void {
		self::settings( array( 'general' => array( 'event_max_rows' => 10000 ) ) );
		self::events( 14000 );
		$result = MaintenanceModule::run( Plugin::instance()->container(), 0.0 );
		$this->assertSame( 1, $result['unfinished'] );
		$this->assertGreaterThan( 0, $result['events'], 'one batch per table even without time left' );
		$this->assertNotFalse( wp_next_scheduled( 'sentinel_shield_maintenance', array( 'more' ) ), 'a follow-up run is due soon' );
		$this->assertLessThanOrEqual( time() + 5 * MINUTE_IN_SECONDS, (int) wp_next_scheduled( 'sentinel_shield_maintenance', array( 'more' ) ) );
		$this->assertSame( 1, get_site_option( MaintenanceModule::REPORT )['unfinished'] );
	}
}
