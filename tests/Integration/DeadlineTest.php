<?php
/**
 * Time budgets are deadlines: nothing starts after them, and what is left
 * continues soon.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Tests\Integration;

use SentinelShield\Audit\AuditExporter;
use SentinelShield\Firewall\EarlyGate;
use SentinelShield\Modules\MaintenanceModule;
use SentinelShield\Plugin;
use SentinelShield\Repository\EventRepository;
use SentinelShield\Settings;
use SentinelShield\Support\Deadline;

/**
 * Review 6 (deadline handling): maintenance passes one deadline through
 * every step, caps network timeouts to the time left, schedules a
 * continuation instead of starting work that cannot fit, and leaves network
 * work (heartbeat, audit delivery) to their own jobs.
 */
final class DeadlineTest extends \WP_UnitTestCase {

	/**
	 * HTTP requests made during a test.
	 *
	 * @var list<string>
	 */
	private array $requests = array();

	public function set_up(): void {
		parent::set_up();
		global $wpdb;
		$wpdb->query( $wpdb->prepare( 'DELETE FROM %i', Plugin::instance()->container()->get( EventRepository::class )->table() ) );
		$this->requests = array();
		add_filter( 'pre_http_request', array( $this, 'record' ), 10, 3 );
	}

	public function tear_down(): void {
		remove_filter( 'pre_http_request', array( $this, 'record' ), 10 );
		foreach ( array( Settings::OPTION, AuditExporter::STATE, MaintenanceModule::REPORT, EarlyGate::STATE, EarlyGate::DIRTY ) as $option ) {
			delete_site_option( $option );
		}
		foreach ( array( AuditExporter::CRON, AuditExporter::HEARTBEAT, EarlyGate::EXPIRY_HOOK ) as $hook ) {
			wp_clear_scheduled_hook( $hook );
		}
		wp_clear_scheduled_hook( 'sentinel_shield_maintenance', array( 'more' ) );
		Plugin::instance()->container()->get( Settings::class )->refresh();
		parent::tear_down();
	}

	/**
	 * Records every HTTP request and fails it.
	 *
	 * @param mixed                $pre  Short-circuit value.
	 * @param array<string, mixed> $args Request arguments.
	 * @param string               $url  URL.
	 */
	public function record( $pre, $args, $url ): \WP_Error {
		$this->requests[] = (string) $url;
		return new \WP_Error( 'http_request_failed', 'not in tests' );
	}

	/**
	 * @param array<string, mixed> $settings Settings.
	 */
	private static function settings( array $settings ): Settings {
		update_site_option( Settings::OPTION, $settings );
		$service = Plugin::instance()->container()->get( Settings::class );
		$service->refresh();
		return $service;
	}

	/**
	 * Inserts events (a security event type, so the audit export sends them).
	 */
	private static function events( int $n, string $event = 'lockout' ): void {
		global $wpdb;
		$table = Plugin::instance()->container()->get( EventRepository::class )->table();
		$at    = gmdate( 'Y-m-d H:i:s', time() - MINUTE_IN_SECONDS );
		for ( $done = 0; $done < $n; $done += 1000 ) {
			$rows = array();
			for ( $i = 0; $i < min( 1000, $n - $done ); $i++ ) {
				$rows[] = $wpdb->prepare( '(%s, %s, %s, %s, %s)', $at, '203.0.113.' . ( $i % 250 ), $event, 'login', 'test' );
			}
			$wpdb->query( "INSERT INTO $table (created_at, ip_text, event, module, reason) VALUES " . implode( ',', $rows ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery -- Prepared rows.
		}
	}

	private static function event_rows(): int {
		global $wpdb;
		return (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM %i', Plugin::instance()->container()->get( EventRepository::class )->table() ) );
	}

	public function test_nothing_starts_after_the_deadline(): void {
		self::settings( array( 'general' => array( 'event_max_rows' => 10000 ) ) );
		self::events( 14000 );
		$result = MaintenanceModule::run( Plugin::instance()->container(), 0.0 );
		$this->assertSame( 0, $result['events'], 'not even one batch once the time is used up' );
		$this->assertSame( 14000, self::event_rows() );
		$this->assertSame( array( 'rules', 'tokens', 'offenses', 'events', 'logins', 'early', 'legacy', 'policy' ), $result['deferred'] );
		$this->assertSame( 1, $result['unfinished'] );
		$next = wp_next_scheduled( 'sentinel_shield_maintenance', array( 'more' ) );
		$this->assertNotFalse( $next, 'the rest continues soon' );
		$this->assertLessThanOrEqual( time() + 5 * MINUTE_IN_SECONDS, (int) $next );
		$this->assertSame( $result['deferred'], get_site_option( MaintenanceModule::REPORT )['deferred'], 'reported' );
	}

	public function test_a_slow_step_stops_at_the_deadline_and_the_later_steps_wait(): void {
		self::settings( array( 'general' => array( 'event_max_rows' => 10000 ) ) );
		self::events( 30000 );
		$table = Plugin::instance()->container()->get( EventRepository::class )->table();
		// Each batch of the event cleanup takes 0.3 s (a busy database).
		$slow = static function ( string $query ) use ( $table ): string {
			if ( str_starts_with( $query, "DELETE FROM `$table`" ) ) {
				usleep( 300000 );
			}
			return $query;
		};
		add_filter( 'query', $slow );
		try {
			$result = MaintenanceModule::run( Plugin::instance()->container(), 1.0 );
		} finally {
			remove_filter( 'query', $slow );
		}
		$this->assertGreaterThan( 0, $result['events'], 'batches ran while there was time' );
		$this->assertLessThan( 20000, $result['events'], 'and stopped at the deadline' );
		$this->assertLessThan( 1.0 + 0.3 + 0.5, $result['seconds'], 'one batch at most runs past the deadline' );
		$this->assertContains( 'policy', $result['deferred'], 'steps after the deadline did not start' );
		$this->assertSame( 1, $result['unfinished'] );
		$this->assertNotFalse( wp_next_scheduled( 'sentinel_shield_maintenance', array( 'more' ) ) );

		$result = MaintenanceModule::run( Plugin::instance()->container(), 30.0 );
		$this->assertSame( 0, $result['unfinished'], 'the continuation finishes the job' );
		$this->assertSame( array(), $result['deferred'] );
		$this->assertSame( 10000, self::event_rows() );
	}

	public function test_a_policy_build_that_would_not_fit_goes_to_its_own_job(): void {
		self::settings( array( 'firewall' => array( 'server_files' => true ) ) );
		$gate  = Plugin::instance()->container()->get( EarlyGate::class );
		$state = array(
			'built'       => time() - HOUR_IN_SECONDS,
			'valid_until' => time() + DAY_IN_SECONDS,
			'generation'  => 7,
			'took'        => 40.0,
		);
		update_site_option( EarlyGate::STATE, $state );
		update_site_option(
			EarlyGate::DIRTY,
			array(
				'since' => time() - 60,
				'last'  => time() - 60,
			)
		);
		wp_clear_scheduled_hook( EarlyGate::EXPIRY_HOOK );
		$this->assertSame( 61.0, EarlyGate::build_estimate( $state ), 'the last build with room to spare' );
		$this->assertSame( 2.0, EarlyGate::build_estimate( array() ) );

		$gate->rebuild_if_dirty( Deadline::in( 20.0 ) );
		$this->assertSame( $state, get_site_option( EarlyGate::STATE ), 'not started: it would not fit' );
		$this->assertNotFalse( get_site_option( EarlyGate::DIRTY ), 'the change is still waiting' );
		$this->assertNotFalse( wp_next_scheduled( EarlyGate::EXPIRY_HOOK ) );
		$this->assertLessThanOrEqual( time(), (int) wp_next_scheduled( EarlyGate::EXPIRY_HOOK ), 'handed to the policy job, due now' );
	}

	public function test_housekeeping_makes_no_network_requests_and_keeps_those_jobs_scheduled(): void {
		self::settings(
			array(
				'audit' => array(
					'webhook_url'   => 'https://audit.example.org/in',
					'heartbeat_url' => 'https://monitor.example.org/ping',
				),
			)
		);
		self::events( 50 );
		update_site_option( AuditExporter::STATE, array( 'cursor' => 0 ) );
		wp_clear_scheduled_hook( AuditExporter::CRON );
		wp_clear_scheduled_hook( AuditExporter::HEARTBEAT );

		MaintenanceModule::run( Plugin::instance()->container(), 30.0 );
		$this->assertSame( array(), $this->requests, 'no heartbeat or delivery inside housekeeping' );
		$this->assertNotFalse( wp_next_scheduled( AuditExporter::HEARTBEAT ), 'the heartbeat has its own job' );
		$this->assertNotFalse( wp_next_scheduled( AuditExporter::CRON ), 'waiting events get a delivery run' );

		self::settings( array() );
		MaintenanceModule::run( Plugin::instance()->container(), 30.0 );
		$this->assertFalse( wp_next_scheduled( AuditExporter::HEARTBEAT ), 'no URL, no heartbeat job' );
	}

	public function test_audit_delivery_caps_its_timeouts_and_continues_when_out_of_time(): void {
		$settings = self::settings( array( 'audit' => array( 'webhook_url' => 'https://audit.example.org/in' ) ) );
		self::events( 450 );
		global $wpdb;
		$first = (int) $wpdb->get_var( $wpdb->prepare( 'SELECT MIN(id) FROM %i', Plugin::instance()->container()->get( EventRepository::class )->table() ) );
		update_site_option( AuditExporter::STATE, array( 'cursor' => $first - 1 ) );
		wp_clear_scheduled_hook( AuditExporter::CRON );
		$timeouts = array();
		$http     = static function ( string $url, array $args ) use ( &$timeouts ): array {
			$timeouts[] = (int) $args['timeout'];
			usleep( 1800000 ); // A slow endpoint: 1.8 s of the 3.6 s left after it.
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
		$exporter = new AuditExporter( $settings, Plugin::instance()->container()->get( EventRepository::class ), $http );
		$deadline = Deadline::in( 3.6 );
		$exporter->run( $deadline );
		$this->assertSame( array( 3 ), $timeouts, 'the timeout is the time left, and no batch starts with under 2 s left' );
		$this->assertTrue( $deadline->was_cut() );
		$this->assertSame( $first + 199, (int) AuditExporter::state()['cursor'], 'the batch sent is recorded' );
		$next = wp_next_scheduled( AuditExporter::CRON );
		$this->assertNotFalse( $next, 'the rest is delivered by the next run' );
		$this->assertLessThanOrEqual( time() + MINUTE_IN_SECONDS, (int) $next );
	}

	public function test_a_deadline_reports_the_time_left_honestly(): void {
		$deadline = Deadline::in( 5.0 );
		$this->assertTrue( $deadline->allows( 4.0 ) );
		$this->assertFalse( $deadline->allows( 6.0 ) );
		$this->assertSame( 4, $deadline->timeout( 10 ), 'capped to the whole seconds left' );
		$this->assertSame( 3, $deadline->timeout( 3 ) );
		$this->assertSame( 0, Deadline::in( 1.5 )->timeout( 10 ), 'under 2 s: do not send' );
		$this->assertTrue( Deadline::in( 0.0 )->expired() );
		$this->assertSame( 10, Deadline::in( INF )->timeout( 10 ) );
		$this->assertFalse( $deadline->was_cut() );
		$deadline->cut();
		$this->assertTrue( $deadline->was_cut() );
	}
}
