<?php
/**
 * Remote audit export, heartbeat and alert delivery tracking.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Tests\Integration;

use SentinelShield\Audit\AuditExporter;
use SentinelShield\Plugin;
use SentinelShield\Repository\EventRepository;
use SentinelShield\Safety\Health;
use SentinelShield\Settings;
use SentinelShield\Support\Mailer;
use SentinelShield\Support\Throttle;

final class AuditTest extends \WP_UnitTestCase {

	/**
	 * Requests the fake endpoint received: [url, args].
	 *
	 * @var list<array{0:string, 1:array<string, mixed>}>
	 */
	private array $sent = array();

	private int $status = 200;

	private ?AuditExporter $exporter = null;

	public function set_up(): void {
		parent::set_up();
		$c = Plugin::instance()->container();
		// The plugin's own exporter would send real requests.
		remove_action( 'sentinel_shield_event_logged', array( $c->get( AuditExporter::class ), 'on_event' ) );
		remove_action( AuditExporter::CRON, array( $c->get( AuditExporter::class ), 'run' ) );
		global $wpdb;
		$wpdb->query( $wpdb->prepare( 'DELETE FROM %i', $c->get( EventRepository::class )->table() ) );
		foreach ( array( AuditExporter::STATE, AuditExporter::SECRET, Mailer::HEALTH ) as $option ) {
			delete_site_option( $option );
		}
		$seen = new \ReflectionProperty( Throttle::class, 'seen' );
		$seen->setAccessible( true );
		$seen->setValue( null, array() );
		$this->sent   = array();
		$this->status = 200;
		reset_phpmailer_instance();
	}

	public function tear_down(): void {
		if ( null !== $this->exporter ) {
			remove_action( AuditExporter::CRON, array( $this->exporter, 'run' ) );
			remove_action( 'sentinel_shield_event_logged', array( $this->exporter, 'on_event' ) );
			remove_action( 'shutdown', array( $this->exporter, 'on_shutdown' ) );
		}
		add_action( 'sentinel_shield_event_logged', array( Plugin::instance()->container()->get( AuditExporter::class ), 'on_event' ), 10, 3 );
		add_action( AuditExporter::CRON, array( Plugin::instance()->container()->get( AuditExporter::class ), 'run' ) );
		wp_clear_scheduled_hook( AuditExporter::CRON );
		delete_site_option( Settings::OPTION );
		Plugin::instance()->container()->get( Settings::class )->refresh();
		parent::tear_down();
	}

	/**
	 * An exporter with a fake HTTP client.
	 *
	 * @param array<string, mixed> $audit audit.* settings.
	 */
	private function exporter( array $audit ): AuditExporter {
		update_site_option( Settings::OPTION, array( 'audit' => $audit ) );
		$settings = Plugin::instance()->container()->get( Settings::class );
		$settings->refresh();
		$this->exporter = new AuditExporter(
			$settings,
			Plugin::instance()->container()->get( EventRepository::class ),
			function ( string $url, array $args ): array {
				$this->sent[] = array( $url, $args );
				return array(
					'response' => array( 'code' => $this->status ),
					'body'     => '',
				);
			}
		);
		$this->exporter->register();
		return $this->exporter;
	}

	/**
	 * Logs an event through the repository (fires the hook).
	 *
	 * @param string $event Event type.
	 */
	private static function log( string $event ): void {
		Plugin::instance()->container()->get( EventRepository::class )->log(
			$event,
			array(
				'ip'     => '203.0.113.9',
				'module' => 'test',
				'reason' => 'test ' . $event,
			)
		);
	}

	/**
	 * Decoded body of a sent request, after checking its signature.
	 *
	 * @param int $n Request number.
	 * @return array<string, mixed>
	 */
	private function body( int $n ): array {
		[ , $args ] = $this->sent[ $n ];
		$this->assertMatchesRegularExpression( '/^t=(\d+),v1=([0-9a-f]{64})$/', $args['headers']['X-Sentinel-Shield-Signature'] );
		preg_match( '/^t=(\d+),v1=([0-9a-f]{64})$/', $args['headers']['X-Sentinel-Shield-Signature'], $m );
		$this->assertSame( hash_hmac( 'sha256', $m[1] . '.' . $args['body'], AuditExporter::secret() ), $m[2], 'signature verifies' );
		return json_decode( $args['body'], true );
	}

	/**
	 * Checks a run of events against the chain rule.
	 *
	 * @param list<array<string, mixed>> $events Events.
	 * @param string                     $prev   Hash before the first.
	 */
	private function assert_chain( array $events, string $prev ): string {
		foreach ( $events as $event ) {
			$this->assertSame( $prev, $event['prev'] );
			$plain = $event;
			unset( $plain['seq'], $plain['prev'], $plain['hash'] );
			$this->assertSame( hash( 'sha256', $prev . "\n" . wp_json_encode( $plain ) ), $event['hash'] );
			$prev = $event['hash'];
		}
		return $prev;
	}

	public function test_events_are_sent_signed_and_chained(): void {
		$export = $this->exporter( array( 'webhook_url' => 'https://logs.example.test/in' ) );
		self::log( 'lockout' );
		self::log( 'blocked' );
		self::log( 'config_change' );
		$export->on_shutdown();
		$this->assertSame( array(), $this->sent, 'nothing is sent during the visitor\'s request' );
		$this->assertNotFalse( wp_next_scheduled( AuditExporter::CRON ), 'delivery is scheduled in the background' );
		do_action( AuditExporter::CRON );

		$this->assertCount( 1, $this->sent );
		$this->assertSame( 'https://logs.example.test/in', $this->sent[0][0] );
		$body = $this->body( 0 );
		$this->assertSame( array( 'lockout', 'config_change' ), array_column( $body['events'], 'event' ), 'routine blocks are left out' );
		$this->assertSame( array( 1, 2 ), array_column( $body['events'], 'seq' ) );
		$last = $this->assert_chain( $body['events'], '' );

		// The next batch continues the chain.
		self::log( 'malware_finding' );
		$export->run();
		$next = $this->body( 1 );
		$this->assertSame( 3, $next['events'][0]['seq'] );
		$this->assert_chain( $next['events'], $last );
		$this->assertSame( 0, $export->backlog() );
		$this->assertSame( 3, AuditExporter::state()['sent'] );

		// "All events" includes blocked requests.
		$this->exporter( array( 'webhook_url' => 'https://logs.example.test/in', 'scope' => 'all' ) );
		$this->assertTrue( $this->exporter->in_scope( 'blocked' ) );
	}

	public function test_undelivered_events_survive_retention_pruning(): void {
		$export = $this->exporter( array( 'webhook_url' => 'https://logs.example.test/in' ) );
		self::log( 'lockout' );
		$this->status = 503;
		$export->run();
		global $wpdb;
		$events = Plugin::instance()->container()->get( EventRepository::class );
		$table  = $events->table();
		self::log( 'lockout' );
		self::log( 'lockout' );
		$ids = array_map( 'intval', $wpdb->get_col( $wpdb->prepare( 'SELECT id FROM %i ORDER BY id', $table ) ) );
		// All three are older than the 30-day retention; the last is older than 90 days.
		$wpdb->query( $wpdb->prepare( 'UPDATE %i SET created_at = %s WHERE id IN (%d, %d)', $table, gmdate( 'Y-m-d H:i:s', time() - 40 * DAY_IN_SECONDS ), $ids[0], $ids[1] ) );
		$wpdb->query( $wpdb->prepare( 'UPDATE %i SET created_at = %s WHERE id = %d', $table, gmdate( 'Y-m-d H:i:s', time() - 100 * DAY_IN_SECONDS ), $ids[2] ) );
		$this->assertSame( 3, $export->backlog() );
		$this->assertGreaterThan( 39 * DAY_IN_SECONDS, time() - $export->oldest_unsent() );

		$export->note_dropped();
		$deleted = $events->prune( 30, $export->retention_cursor(), AuditExporter::KEEP_UNSENT_DAYS );
		$this->assertSame( 1, $deleted, 'only the undelivered event older than 90 days is pruned' );
		$this->assertSame( 2, $export->backlog() );
		$this->assertSame( 1, AuditExporter::state()['dropped'], 'and counted as a gap' );

		// Without a webhook, retention applies to everything.
		$this->assertSame( 2, $events->prune( 30 ) );
	}

	public function test_failures_back_off_and_keep_the_events(): void {
		$export = $this->exporter( array( 'webhook_url' => 'https://logs.example.test/in' ) );
		$this->status = 503;
		self::log( 'lockout' );
		$state = $export->run();
		$this->assertSame( 1, $state['failures'] );
		$this->assertStringContainsString( '503', $state['error'] );
		$this->assertEqualsWithDelta( time() + 60, $state['next_try'], 5 );
		$this->assertNotFalse( wp_next_scheduled( AuditExporter::CRON ) );
		$this->assertSame( 1, $export->backlog() );

		$state = $export->run();
		$this->assertEqualsWithDelta( time() + 120, $state['next_try'], 5, 'the delay doubles' );

		$this->status = 200;
		self::log( 'unlock' );
		$state = $export->run();
		$this->assertSame( 0, $state['failures'] );
		$this->assertSame( 0, $export->backlog() );
		$body = $this->body( count( $this->sent ) - 1 );
		$this->assertSame( array( 1, 2 ), array_column( $body['events'], 'seq' ), 'nothing lost or skipped' );
	}

	public function test_heartbeat_and_test_channels(): void {
		$export = $this->exporter(
			array(
				'webhook_url'   => 'https://logs.example.test/in',
				'heartbeat_url' => 'https://hc.example.test/ping/abc',
			)
		);
		$export->heartbeat();
		$this->assertSame( 'https://hc.example.test/ping/abc', end( $this->sent )[0] );
		$this->assertTrue( AuditExporter::state()['heartbeat']['ok'] );

		$results = $export->test();
		$this->assertArrayHasKey( 'email', $results );
		$this->assertSame( 'Delivered (HTTP 2xx).', $results['webhook'] );
		$this->assertSame( 'Pinged.', $results['heartbeat'] );

		$this->status = 404;
		$export->heartbeat();
		$this->assertFalse( AuditExporter::state()['heartbeat']['ok'] );
		$checks = array_column( ( new Health( Plugin::instance()->container() ) )->checks(), null, 'id' );
		$this->assertSame( 'warn', $checks['heartbeat']['state'] );
	}

	public function test_failed_alert_emails_are_recorded_and_reported(): void {
		$this->assertTrue( Mailer::send( 'admin@example.org', 'Subject', 'Body', 'alert' ) );
		$this->assertFalse( Mailer::failing( 'alert' ) );

		$fail = static function () {
			do_action( 'wp_mail_failed', new \WP_Error( 'wp_mail_failed', 'SMTP connect() failed.' ) );
			return false;
		};
		add_filter( 'pre_wp_mail', $fail );
		$this->assertFalse( Mailer::send( 'admin@example.org', 'Subject', 'Body', 'alert' ) );
		remove_filter( 'pre_wp_mail', $fail );
		$this->assertTrue( Mailer::failing( 'alert' ) );
		$this->assertSame( 'SMTP connect() failed.', Mailer::health()['alert']['error'] );

		$checks = array_column( ( new Health( Plugin::instance()->container() ) )->checks(), null, 'id' );
		$this->assertSame( 'bad', $checks['mail']['state'] );
		$this->assertStringContainsString( 'SMTP connect() failed.', $checks['mail']['detail'] );

		$this->assertTrue( Mailer::send( 'admin@example.org', 'Subject', 'Body', 'alert' ) );
		$this->assertFalse( Mailer::failing( 'alert' ), 'a later success clears it' );
	}
}
