<?php
/**
 * Sends security events off the site as they happen.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Audit;

use SentinelShield\Repository\EventRepository;
use SentinelShield\Settings;
use SentinelShield\Support\Mailer;
use SentinelShield\Support\Mutex;
use SentinelShield\Support\Throttle;

defined( 'ABSPATH' ) || exit;

/**
 * Whoever takes over a site can empty its database, and with it the event
 * log. Sending events elsewhere as they happen keeps the evidence:
 *
 * - Webhook: batches of events are POSTed as JSON to an HTTPS endpoint (a SIEM,
 *   log service or your own script), signed with HMAC-SHA256. Each event
 *   carries a sequence number and a hash chained to the previous event, so the
 *   receiver can tell when events are missing or were altered. Events are sent
 *   when the request that logged them ends, and retried with backoff.
 * - Syslog: each event is also written to the server's syslog (facility auth),
 *   which the server can forward elsewhere.
 * - Heartbeat: an hourly ping to a monitoring URL; the monitoring service
 *   raises the alarm when the pings stop (site down, plugin disabled, cron dead).
 */
final class AuditExporter {

	public const CRON   = 'sentinel_shield_audit_export';
	public const STATE  = 'sentinel_shield_audit_state';
	public const SECRET = 'sentinel_shield_audit_secret';
	public const BATCH  = 200;

	/**
	 * Event types left out of the "security events" scope (high volume).
	 */
	public const NOISY = array( 'blocked', 'would_block' );

	/**
	 * Whether an export is queued for the end of this request.
	 *
	 * @var bool
	 */
	private bool $queued = false;

	/**
	 * Sends an HTTP request: fn( string $url, array $args ): array|\WP_Error.
	 *
	 * @var \Closure
	 */
	private \Closure $http;

	/**
	 * Constructor.
	 *
	 * @param Settings        $settings Settings.
	 * @param EventRepository $events   Event log.
	 * @param \Closure|null   $http     HTTP client (defaults to wp_safe_remote_request()).
	 */
	public function __construct( private Settings $settings, private EventRepository $events, ?\Closure $http = null ) {
		$this->http = $http ?? static fn( string $url, array $args ) => wp_safe_remote_request( $url, $args );
	}

	/**
	 * Hooks the exporter.
	 */
	public function register(): void {
		add_action( 'sentinel_shield_event_logged', array( $this, 'on_event' ), 10, 3 );
		add_action( self::CRON, array( $this, 'run' ) );
	}

	/**
	 * Webhook URL, or ''.
	 */
	public function webhook(): string {
		return (string) $this->settings->get( 'audit.webhook_url', '' );
	}

	/**
	 * The signing secret (created on first use).
	 */
	public static function secret(): string {
		$secret = get_site_option( self::SECRET );
		if ( ! is_string( $secret ) || strlen( $secret ) < 32 ) {
			$secret = bin2hex( random_bytes( 32 ) );
			update_site_option( self::SECRET, $secret );
		}
		return $secret;
	}

	/**
	 * Replaces the signing secret.
	 */
	public static function new_secret(): string {
		delete_site_option( self::SECRET );
		return self::secret();
	}

	/**
	 * Export state: cursor, seq, hash, last_ok, last_error, failures, next_try, sent, heartbeat.
	 *
	 * @return array<string, mixed>
	 */
	public static function state(): array {
		$state = get_site_option( self::STATE );
		return is_array( $state ) ? $state : array();
	}

	/**
	 * Whether an event type is exported.
	 *
	 * @param string $event Event type.
	 */
	public function in_scope( string $event ): bool {
		return 'all' === $this->settings->get( 'audit.scope', 'security' ) || ! in_array( $event, self::NOISY, true );
	}

	/**
	 * `sentinel_shield_event_logged`: syslog right away; webhook at the end of the request.
	 *
	 * @param int                  $id    Row ID.
	 * @param string               $event Event type.
	 * @param array<string, mixed> $data  Event data.
	 */
	public function on_event( $id, $event, $data = array() ): void {
		$event = (string) $event;
		if ( ! $this->in_scope( $event ) ) {
			return;
		}
		if ( $this->settings->get( 'audit.syslog', false ) && function_exists( 'syslog' ) ) {
			$this->syslog( (int) $id, $event, (array) $data );
		}
		if ( '' !== $this->webhook() && ! isset( self::state()['cursor'] ) ) {
			// First event since the webhook was set up: the export starts here.
			$state           = self::state();
			$state['cursor'] = max( 0, (int) $id - 1 );
			update_site_option( self::STATE, $state );
		}
		if ( '' !== $this->webhook() && ! $this->queued ) {
			$this->queued = true;
			add_action( 'shutdown', array( $this, 'on_shutdown' ) );
		}
	}

	/**
	 * End of a request that logged events: schedules delivery in the
	 * background (WP-Cron) instead of making a visitor's request wait on the
	 * endpoint. The event table is the durable queue; nothing is lost if a run
	 * fails, it is retried with increasing delays.
	 */
	public function on_shutdown(): void {
		$state = self::state();
		$when  = max( time(), (int) ( $state['next_try'] ?? 0 ) );
		if ( ! wp_next_scheduled( self::CRON ) ) {
			wp_schedule_single_event( $when, self::CRON );
		}
	}

	/**
	 * Sends pending events in batches until done, out of time, or failing.
	 *
	 * @param float $budget Seconds.
	 * @return array<string, mixed> The state afterwards.
	 */
	public function run( $budget = 15.0 ): array {
		if ( '' === $this->webhook() || ! Mutex::acquire( 'audit_export', 0 ) ) {
			return self::state();
		}
		try {
			$until = microtime( true ) + (float) $budget;
			do {
				Mutex::renew( 'audit_export' );
				$state = self::state();
				$rows  = $this->pending( (int) ( $state['cursor'] ?? $this->start_cursor() ) );
				if ( ! $rows ) {
					break;
				}
				[ $events, $seq, $hash ] = self::chain( $rows, (int) ( $state['seq'] ?? 0 ), (string) ( $state['hash'] ?? '' ) );
				$result                  = $this->post( $events );
				if ( true !== $result ) {
					$failures          = (int) ( $state['failures'] ?? 0 ) + 1;
					$state['failures'] = $failures;
					$state['error']    = $result;
					$state['failed']   = time();
					$state['next_try'] = time() + min( HOUR_IN_SECONDS, MINUTE_IN_SECONDS * ( 2 ** min( 6, $failures - 1 ) ) );
					update_site_option( self::STATE, $state );
					wp_clear_scheduled_hook( self::CRON );
					wp_schedule_single_event( (int) $state['next_try'], self::CRON );
					return $state;
				}
				$last              = end( $rows );
				$state['cursor']   = (int) $last['id'];
				$state['seq']      = $seq;
				$state['hash']     = $hash;
				$state['last_ok']  = time();
				$state['sent']     = (int) ( $state['sent'] ?? 0 ) + count( $events );
				$state['failures'] = 0;
				$state['next_try'] = 0;
				$state['error']    = '';
				update_site_option( self::STATE, $state );
				$full = count( $rows ) === self::BATCH;
			} while ( $full && microtime( true ) < $until );
			return self::state();
		} finally {
			Mutex::release( 'audit_export' );
		}
	}

	/**
	 * Number of exportable events not sent yet.
	 */
	public function backlog(): int {
		global $wpdb;
		$cursor = (int) ( self::state()['cursor'] ?? $this->start_cursor() );
		$sql    = 'all' === $this->settings->get( 'audit.scope', 'security' )
			? $wpdb->prepare( 'SELECT COUNT(*) FROM %i WHERE id > %d', $this->events->table(), $cursor )
			: $wpdb->prepare( 'SELECT COUNT(*) FROM %i WHERE id > %d AND event NOT IN (%s, %s)', $this->events->table(), $cursor, self::NOISY[0], self::NOISY[1] );
		return (int) $wpdb->get_var( $sql ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery -- Prepared above; live count.
	}

	/**
	 * Undelivered events older than this many days are pruned anyway (and
	 * counted as a delivery gap).
	 */
	public const KEEP_UNSENT_DAYS = 90;

	/**
	 * The last delivered event ID while a webhook is set (retention pruning
	 * keeps everything after it), or null.
	 */
	public function retention_cursor(): ?int {
		if ( '' === $this->webhook() ) {
			return null;
		}
		$state = self::state();
		return isset( $state['cursor'] ) ? (int) $state['cursor'] : null;
	}

	/**
	 * Before pruning: counts undelivered events that are too old to keep, so
	 * the gap in the remote log is visible.
	 */
	public function note_dropped(): void {
		$cursor = $this->retention_cursor();
		if ( null === $cursor ) {
			return;
		}
		$n = $this->events->count_undelivered_older( $cursor, self::KEEP_UNSENT_DAYS );
		if ( $n > 0 ) {
			$state            = self::state();
			$state['dropped'] = (int) ( $state['dropped'] ?? 0 ) + $n;
			$state['gap']     = time();
			update_site_option( self::STATE, $state );
		}
	}

	/**
	 * Time of the oldest exportable event not sent yet, or 0.
	 */
	public function oldest_unsent(): int {
		global $wpdb;
		$cursor = $this->retention_cursor();
		if ( null === $cursor ) {
			return 0;
		}
		$created = (string) $wpdb->get_var( $wpdb->prepare( 'SELECT created_at FROM %i WHERE id > %d ORDER BY id LIMIT 1', $this->events->table(), $cursor ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Live value.
		return '' === $created ? 0 : (int) strtotime( $created . ' UTC' );
	}

	/**
	 * Where a fresh export starts when no event has set it yet: after the
	 * newest event (events logged before the webhook was set up are not sent;
	 * use WP-CLI audit-export for those).
	 */
	private function start_cursor(): int {
		global $wpdb;
		$state           = self::state();
		$state['cursor'] = (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COALESCE(MAX(id), 0) FROM %i', $this->events->table() ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Live value.
		update_site_option( self::STATE, $state );
		return (int) $state['cursor'];
	}

	/**
	 * Exportable events after a cursor, oldest first.
	 *
	 * @param int $cursor Last exported ID.
	 * @return list<array<string, mixed>>
	 */
	private function pending( int $cursor ): array {
		global $wpdb;
		if ( 'all' === $this->settings->get( 'audit.scope', 'security' ) ) {
			$rows = $wpdb->get_results( $wpdb->prepare( 'SELECT id, created_at, ip_text, event, module, reason, uri, user_agent, user_id, is_test, context FROM %i WHERE id > %d ORDER BY id LIMIT %d', $this->events->table(), $cursor, self::BATCH ), ARRAY_A ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Live rows.
		} else {
			$rows = $wpdb->get_results( $wpdb->prepare( 'SELECT id, created_at, ip_text, event, module, reason, uri, user_agent, user_id, is_test, context FROM %i WHERE id > %d AND event NOT IN (%s, %s) ORDER BY id LIMIT %d', $this->events->table(), $cursor, self::NOISY[0], self::NOISY[1], self::BATCH ), ARRAY_A ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Live rows.
		}
		return is_array( $rows ) ? $rows : array();
	}

	/**
	 * Adds sequence numbers and the hash chain to event rows.
	 *
	 * Each hash is sha256( previous hash . "\n" . JSON of the event without seq/prev/hash ).
	 *
	 * @param list<array<string, mixed>> $rows Event rows.
	 * @param int                        $seq  Last sequence number.
	 * @param string                     $prev Last hash.
	 * @return array{0:list<array<string, mixed>>, 1:int, 2:string}
	 */
	public static function chain( array $rows, int $seq, string $prev ): array {
		$out = array();
		foreach ( $rows as $row ) {
			$event = array(
				'id'      => (int) $row['id'],
				'time'    => (string) $row['created_at'] . 'Z',
				'event'   => (string) $row['event'],
				'module'  => (string) $row['module'],
				'ip'      => (string) $row['ip_text'],
				'reason'  => (string) $row['reason'],
				'uri'     => (string) $row['uri'],
				'agent'   => (string) $row['user_agent'],
				'user_id' => (int) $row['user_id'],
				'test'    => (bool) (int) $row['is_test'],
				'context' => json_decode( (string) $row['context'], true ),
			);
			$hash  = hash( 'sha256', $prev . "\n" . wp_json_encode( $event ) );
			$out[] = array(
				'seq'  => ++$seq,
				'prev' => $prev,
				'hash' => $hash,
			) + $event;
			$prev  = $hash;
		}
		return array( $out, $seq, $prev );
	}

	/**
	 * POSTs a batch. Returns true, or the error message.
	 *
	 * @param list<array<string, mixed>> $events Events with chain.
	 */
	private function post( array $events ): string|bool {
		$body     = (string) wp_json_encode(
			array(
				'site'   => home_url( '/' ),
				'source' => 'sentinel-shield',
				'sent'   => gmdate( 'c' ),
				'events' => $events,
			)
		);
		$time     = (string) time();
		$response = ( $this->http )(
			$this->webhook(),
			array(
				'method'  => 'POST',
				'timeout' => 10,
				'headers' => array(
					'Content-Type'                => 'application/json',
					'X-Sentinel-Shield-Signature' => 't=' . $time . ',v1=' . hash_hmac( 'sha256', $time . '.' . $body, self::secret() ),
				),
				'body'    => $body,
			)
		);
		if ( is_wp_error( $response ) ) {
			return $response->get_error_message();
		}
		$code = (int) wp_remote_retrieve_response_code( $response );
		/* translators: %d: HTTP status code. */
		return $code >= 200 && $code < 300 ? true : sprintf( __( 'The endpoint answered HTTP %d.', 'sentinel-shield' ), $code );
	}

	/**
	 * Writes one event to syslog.
	 *
	 * @param int                  $id    Row ID.
	 * @param string               $event Event type.
	 * @param array<string, mixed> $data  Event data.
	 */
	private function syslog( int $id, string $event, array $data ): void {
		$critical = array( 'malware_finding', 'integrity_finding', 'lockdown_admin_added', 'lockdown_admin_denied', 'lockdown_tamper', 'twofa_failed', 'account_attack' );
		$priority = in_array( $event, $critical, true ) ? LOG_WARNING : LOG_NOTICE;
		openlog( 'sentinel-shield', LOG_PID | LOG_ODELAY, LOG_AUTH );
		syslog(
			$priority,
			(string) wp_json_encode(
				array(
					'site'   => wp_parse_url( home_url(), PHP_URL_HOST ),
					'id'     => $id,
					'event'  => $event,
					'module' => (string) ( $data['module'] ?? '' ),
					'ip'     => (string) ( $data['ip'] ?? '' ),
					'reason' => (string) ( $data['reason'] ?? '' ),
				)
			)
		);
		closelog();
	}

	/**
	 * Hourly heartbeat ping; records the result.
	 */
	public function heartbeat(): void {
		$url = (string) $this->settings->get( 'audit.heartbeat_url', '' );
		if ( '' === $url ) {
			return;
		}
		$response           = ( $this->http )(
			$url,
			array(
				'method'  => 'GET',
				'timeout' => 10,
			)
		);
		$ok                 = ! is_wp_error( $response ) && (int) wp_remote_retrieve_response_code( $response ) < 400;
		$state              = self::state();
		$state['heartbeat'] = array(
			'time'  => time(),
			'ok'    => $ok,
			'error' => $ok ? '' : ( is_wp_error( $response ) ? $response->get_error_message() : 'HTTP ' . (int) wp_remote_retrieve_response_code( $response ) ),
		);
		update_site_option( self::STATE, $state );
	}

	/**
	 * Sends a test through every configured channel.
	 *
	 * @return array<string, string> Channel => result text.
	 */
	public function test(): array {
		$out   = array();
		$email = (string) get_site_option( 'admin_email' );
		$sent  = Mailer::send(
			$email,
			/* translators: %s: site name. */
			sprintf( __( '[%s] Sentinel Shield test alert', 'sentinel-shield' ), wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ) ),
			__( 'This is a test of Sentinel Shield\'s alert emails. If you received it, security alerts reach you.', 'sentinel-shield' ),
			'test'
		);
		/* translators: %s: email address. */
		$out['email'] = $sent ? sprintf( __( 'Sent to %s (check that it arrives).', 'sentinel-shield' ), $email ) : (string) ( Mailer::health()['test']['error'] ?? __( 'Failed.', 'sentinel-shield' ) );
		if ( '' !== $this->webhook() ) {
			[ $events ]     = self::chain(
				array(
					array(
						'id'         => 0,
						'created_at' => gmdate( 'Y-m-d H:i:s' ),
						'ip_text'    => '',
						'event'      => 'audit_test',
						'module'     => 'audit',
						'reason'     => 'Test event from the Sentinel Shield settings',
						'uri'        => '',
						'user_agent' => '',
						'user_id'    => get_current_user_id(),
						'is_test'    => 1,
						'context'    => '',
					),
				),
				0,
				''
			);
			$result         = $this->post( $events );
			$out['webhook'] = true === $result ? __( 'Delivered (HTTP 2xx).', 'sentinel-shield' ) : (string) $result;
		}
		if ( '' !== (string) $this->settings->get( 'audit.heartbeat_url', '' ) ) {
			$this->heartbeat();
			$beat             = (array) ( self::state()['heartbeat'] ?? array() );
			$out['heartbeat'] = ! empty( $beat['ok'] ) ? __( 'Pinged.', 'sentinel-shield' ) : (string) ( $beat['error'] ?? '' );
		}
		if ( $this->settings->get( 'audit.syslog', false ) && function_exists( 'syslog' ) ) {
			$this->syslog(
				0,
				'audit_test',
				array(
					'module' => 'audit',
					'reason' => 'Test event from the Sentinel Shield settings',
				)
			);
			$out['syslog'] = __( 'Written (check your system log).', 'sentinel-shield' );
		}
		return $out;
	}
}
