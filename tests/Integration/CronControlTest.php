<?php
/**
 * Cron controls: run now, pause/resume (and the re-add guard), reschedule, delete.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Tests\Integration;

use SentinelShield\Cron\CronControl;
use SentinelShield\Install\Installer;

final class CronControlTest extends \WP_UnitTestCase {

	public function set_up(): void {
		parent::set_up();
		delete_option( CronControl::PAUSED_OPTION );
		add_filter( 'pre_http_request', static fn() => array( 'response' => array( 'code' => 200 ), 'body' => '' ) );
	}

	public function tear_down(): void {
		delete_option( CronControl::PAUSED_OPTION );
		foreach ( array( 'ss_ctl_job', 'ss_ctl_once' ) as $hook ) {
			wp_clear_scheduled_hook( $hook );
			wp_clear_scheduled_hook( $hook, array( 'a' ) );
		}
		parent::tear_down();
	}

	/**
	 * @return array<string, mixed>
	 */
	private function event( string $hook, array $args = array() ): array {
		$ts = wp_next_scheduled( $hook, $args );
		$this->assertIsInt( $ts, "$hook should be scheduled" );
		return CronControl::find( $ts, $hook, md5( serialize( $args ) ) );
	}

	public function test_find_requires_exact_event(): void {
		$ts = time() + 3600;
		wp_schedule_event( $ts, 'daily', 'ss_ctl_job', array( 'a' ) );
		$this->assertNotNull( CronControl::find( $ts, 'ss_ctl_job', md5( serialize( array( 'a' ) ) ) ) );
		$this->assertNull( CronControl::find( $ts, 'ss_ctl_job', md5( serialize( array( 'b' ) ) ) ) );
		$this->assertNull( CronControl::find( $ts + 1, 'ss_ctl_job', md5( serialize( array( 'a' ) ) ) ) );
		$this->assertNull( CronControl::find( $ts, 'wp_version_check', md5( serialize( array( 'a' ) ) ) ) );
	}

	public function test_run_now_moves_event_to_now_and_keeps_schedule(): void {
		wp_schedule_event( time() + DAY_IN_SECONDS, 'daily', 'ss_ctl_job', array( 'a' ) );
		$this->assertTrue( CronControl::run_now( $this->event( 'ss_ctl_job', array( 'a' ) ) ) );
		$this->assertLessThanOrEqual( time(), wp_next_scheduled( 'ss_ctl_job', array( 'a' ) ) );
		$this->assertSame( 'daily', wp_get_schedule( 'ss_ctl_job', array( 'a' ) ) );
	}

	public function test_pause_blocks_plugin_from_re_adding_until_resume(): void {
		$ts = time() + 7200;
		wp_schedule_event( $ts, 'hourly', 'ss_ctl_job', array( 'a' ) );
		$this->assertTrue( CronControl::pause( $this->event( 'ss_ctl_job', array( 'a' ) ), 1 ) );
		$this->assertFalse( wp_next_scheduled( 'ss_ctl_job', array( 'a' ) ) );

		// What a typical plugin does on every page load:
		$this->assertFalse( wp_schedule_event( time(), 'hourly', 'ss_ctl_job', array( 'a' ) ) );
		$this->assertFalse( wp_next_scheduled( 'ss_ctl_job', array( 'a' ) ) );
		// Same hook with different arguments is a different task and is not blocked.
		$this->assertTrue( wp_schedule_event( time(), 'hourly', 'ss_ctl_job', array( 'b' ) ) );
		wp_clear_scheduled_hook( 'ss_ctl_job', array( 'b' ) );

		$key = CronControl::paused_key( 'ss_ctl_job', array( 'a' ) );
		$this->assertTrue( CronControl::resume( $key ) );
		$this->assertSame( $ts, wp_next_scheduled( 'ss_ctl_job', array( 'a' ) ), 'Resumes at its original time when that is still ahead.' );
		$this->assertSame( 'hourly', wp_get_schedule( 'ss_ctl_job', array( 'a' ) ) );
		$this->assertSame( array(), CronControl::paused() );
	}

	public function test_pause_and_resume_one_off_event_in_the_past(): void {
		wp_schedule_single_event( time() - 30, 'ss_ctl_once' );
		CronControl::pause( $this->event( 'ss_ctl_once' ), 1 );
		$this->assertFalse( wp_schedule_single_event( time(), 'ss_ctl_once' ) );
		CronControl::resume( CronControl::paused_key( 'ss_ctl_once', array() ) );
		$next = wp_next_scheduled( 'ss_ctl_once' );
		$this->assertGreaterThanOrEqual( time() + 55, $next );
		$this->assertFalse( wp_get_schedule( 'ss_ctl_once' ) );
	}

	public function test_reschedule_changes_recurrence_and_time(): void {
		wp_schedule_event( time() + 3600, 'hourly', 'ss_ctl_job' );
		$next = time() + 2 * DAY_IN_SECONDS;
		$this->assertTrue( CronControl::reschedule( $this->event( 'ss_ctl_job' ), 'weekly', $next ) );
		$this->assertSame( $next, wp_next_scheduled( 'ss_ctl_job' ) );
		$this->assertSame( 'weekly', wp_get_schedule( 'ss_ctl_job' ) );

		$this->assertTrue( CronControl::reschedule( $this->event( 'ss_ctl_job' ), '', $next ) );
		$this->assertFalse( wp_get_schedule( 'ss_ctl_job' ), 'Now a one-off.' );

		$this->assertWPError( CronControl::reschedule( $this->event( 'ss_ctl_job' ), 'every_nanosecond', $next ) );
		$this->assertWPError( CronControl::reschedule( $this->event( 'ss_ctl_job' ), 'daily', time() + 20 * YEAR_IN_SECONDS ) );
		$this->assertSame( $next, wp_next_scheduled( 'ss_ctl_job' ), 'Rejected changes leave the task as it was.' );
	}

	public function test_delete_and_forget(): void {
		wp_schedule_event( time() + 3600, 'hourly', 'ss_ctl_job' );
		$this->assertTrue( CronControl::delete( $this->event( 'ss_ctl_job' ) ) );
		$this->assertFalse( wp_next_scheduled( 'ss_ctl_job' ) );

		wp_schedule_event( time() + 3600, 'hourly', 'ss_ctl_job' );
		CronControl::pause( $this->event( 'ss_ctl_job' ), 1 );
		$this->assertTrue( CronControl::forget( CronControl::paused_key( 'ss_ctl_job', array() ) ) );
		$this->assertTrue( wp_schedule_event( time(), 'hourly', 'ss_ctl_job' ), 'No longer blocked once forgotten.' );
	}

	public function test_deactivation_resumes_paused_tasks(): void {
		wp_schedule_event( time() + 3600, 'hourly', 'ss_ctl_job' );
		CronControl::pause( $this->event( 'ss_ctl_job' ), 1 );
		Installer::deactivate();
		$this->assertNotFalse( wp_next_scheduled( 'ss_ctl_job' ) );
		$this->assertSame( array(), CronControl::paused() );
	}
}
