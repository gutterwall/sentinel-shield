<?php
/**
 * WP-Cron monitor: run recording, failure capture and callback attribution.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Tests\Integration;

use SentinelShield\Cron\CronInspector;
use SentinelShield\Cron\CronRecorder;

/**
 * A named callback so attribution can be checked.
 */
function sentinel_test_cron_job( string $who = '' ): void {
	unset( $who );
	usleep( 20000 );
}

final class CronMonitorTest extends \WP_UnitTestCase {

	public function set_up(): void {
		parent::set_up();
		delete_option( CronRecorder::OPTION );
		$this->reset_recorder();
		add_filter( 'wp_doing_cron', '__return_true' );
	}

	public function tear_down(): void {
		remove_filter( 'wp_doing_cron', '__return_true' );
		$this->reset_recorder();
		wp_clear_scheduled_hook( 'ss_test_job', array( 'alice' ) );
		wp_clear_scheduled_hook( 'ss_test_crash' );
		wp_clear_scheduled_hook( 'ss_test_filter' );
		parent::tear_down();
	}

	private function reset_recorder(): void {
		$prop = new \ReflectionProperty( CronRecorder::class, 'active' );
		$prop->setAccessible( true );
		$prop->setValue( null, null );
	}

	private function recorder(): CronRecorder {
		$prop = new \ReflectionProperty( CronRecorder::class, 'active' );
		$prop->setAccessible( true );
		return $prop->getValue();
	}

	public function test_successful_run_is_recorded_with_its_callbacks(): void {
		wp_schedule_event( time() - HOUR_IN_SECONDS, 'hourly', 'ss_test_job', array( 'alice' ) );
		add_action( 'ss_test_job', __NAMESPACE__ . '\\sentinel_test_cron_job' );
		CronRecorder::maybe_start();
		do_action_ref_array( 'ss_test_job', array( 'alice' ) );
		$this->recorder()->shutdown();

		$run = CronRecorder::runs()[ CronRecorder::key( 'ss_test_job', array( 'alice' ) ) ];
		$this->assertSame( 'ok', $run['status'] );
		$this->assertSame( 'cron', $run['context'] );
		$this->assertSame( 1, $run['count'] );
		$this->assertGreaterThanOrEqual( 0.015, $run['duration'] );
		$this->assertSame( '["alice"]', $run['args'] );
		$this->assertStringContainsString( 'sentinel_test_cron_job', $run['callbacks'][0]['name'] );
		$this->assertStringContainsString( 'CronMonitorTest.php', $run['callbacks'][0]['file'] );
		$this->assertGreaterThan( 0, CronRecorder::last_request() );

		$event = array_values( array_filter( CronInspector::events(), static fn( array $e ): bool => 'ss_test_job' === $e['hook'] ) )[0];
		$this->assertSame( 'ok', $event['run']['status'] );
		$this->assertSame( 'Once Hourly', $event['recurs'] );
		$this->assertSame( 'wp cron event run ss_test_job', CronInspector::command( 'ss_test_job' ) );
		$this->assertSame( 1, CronInspector::health( CronInspector::events() )['overdue'] );
	}

	public function test_crashing_job_is_recorded_as_failed_and_counts_repeats(): void {
		wp_schedule_single_event( time() + 3600, 'ss_test_crash' );
		add_action(
			'ss_test_crash',
			static function (): void {
				throw new \RuntimeException( 'boom' );
			}
		);
		for ( $i = 0; $i < 2; $i++ ) {
			$this->reset_recorder();
			CronRecorder::maybe_start();
			try {
				do_action_ref_array( 'ss_test_crash', array() ); // As wp-cron.php calls it.
			} catch ( \RuntimeException $e ) {
				unset( $e );
			}
			$this->recorder()->shutdown();
		}
		$run = CronRecorder::runs()[ CronRecorder::key( 'ss_test_crash', array() ) ];
		$this->assertSame( 'failed', $run['status'] );
		$this->assertStringContainsString( 'Did not finish', $run['error'] );
		$this->assertSame( 2, $run['failures'] );
		$this->assertSame( 2, $run['count'] );
	}

	public function test_recorder_does_not_change_filter_values(): void {
		wp_schedule_single_event( time() + 3600, 'ss_test_filter' );
		add_filter( 'ss_test_filter', static fn( string $v ): string => $v . '!' );
		CronRecorder::maybe_start();
		$this->assertSame( 'hi!', apply_filters( 'ss_test_filter', 'hi' ) );
	}

	public function test_not_recording_outside_cron(): void {
		remove_filter( 'wp_doing_cron', '__return_true' );
		wp_schedule_single_event( time() + 3600, 'ss_test_filter' );
		CronRecorder::maybe_start();
		$prop = new \ReflectionProperty( CronRecorder::class, 'active' );
		$prop->setAccessible( true );
		$this->assertNull( $prop->getValue() );
	}

	public function test_unscheduled_runs_are_listed_separately(): void {
		wp_schedule_single_event( time() + 3600, 'ss_test_filter' );
		CronRecorder::maybe_start();
		do_action_ref_array( 'ss_test_filter', array() );
		$this->recorder()->shutdown();
		$this->assertSame( array(), CronInspector::past_only( CronInspector::events() ) );
		wp_clear_scheduled_hook( 'ss_test_filter' );
		$past = CronInspector::past_only( CronInspector::events() );
		$this->assertSame( 'ss_test_filter', $past[0]['hook'] );
	}

	public function test_callback_origin_labels(): void {
		$uploads = wp_get_upload_dir()['basedir'];
		$this->assertSame( array( 'uploads folder', 'warning' ), CronInspector::origin( $uploads . '/2026/10/x.php' ) );
		$this->assertSame( array( 'plugin: akismet', '' ), CronInspector::origin( WP_PLUGIN_DIR . '/akismet/akismet.php' ) );
		$this->assertSame( array( 'must-use plugin: solid-launcher-box.php', 'notice' ), CronInspector::origin( WPMU_PLUGIN_DIR . '/solid-launcher-box.php' ) );
		$this->assertSame( array( 'WordPress core', '' ), CronInspector::origin( ABSPATH . WPINC . '/functions.php' ) );
		$this->assertSame( 'warning', CronInspector::origin( '/var/www/x.php(12) : eval()\'d code' )[1] );

		$closure = CronInspector::describe( static function (): void {} );
		$this->assertSame( 'Closure', $closure['name'] );
		$this->assertStringContainsString( 'CronMonitorTest.php', $closure['file'] );
		$this->assertSame( 'wp_version_check', CronInspector::describe( 'wp_version_check' )['name'] );
		$this->assertSame( 'WordPress core', CronInspector::describe( 'wp_version_check' )['source'] );
		$this->assertSame( "wp cron event run 'bad hook;rm'", CronInspector::command( 'bad hook;rm' ) );
	}
}
