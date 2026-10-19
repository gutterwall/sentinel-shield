<?php
/**
 * Cloudflare API contract: the sync recovers from everything the API and the
 * network can do to it.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Tests\Integration;

use SentinelShield\Firewall\CloudflareSync;
use SentinelShield\Firewall\EarlyGate;
use SentinelShield\Firewall\RuleCache;
use SentinelShield\Net\Cidr;
use SentinelShield\Plugin;
use SentinelShield\Repository\BlockRepository;
use SentinelShield\Settings;
use SentinelShield\Support\DataDir;

/**
 * A stateful stand-in for Cloudflare's list API: lists per account, tokens,
 * asynchronous bulk operations that take a number of polls to finish, and
 * faults queued for the next requests.
 */
final class FakeCloudflare {

	/**
	 * Items per "account/list".
	 *
	 * @var array<string, list<string>>
	 */
	public array $lists = array();

	/**
	 * Tokens Cloudflare accepts.
	 *
	 * @var array<string, bool>
	 */
	public array $tokens = array( 'token-a' => true );

	/**
	 * Bulk operations: id => {key, items, polls, fail}.
	 *
	 * @var array<string, array<string, mixed>>
	 */
	public array $ops = array();

	/**
	 * Faults for the next requests, in order: timeout, timeout_after_apply,
	 * rate_limited, malformed, server_error.
	 *
	 * @var list<string>
	 */
	public array $faults = array();

	/**
	 * Polls a new operation needs before it completes.
	 */
	public int $polls = 1;

	/**
	 * Whether new operations end as failed.
	 */
	public bool $fail_ops = false;

	/**
	 * Lists ("account/list") whose uploads are refused (400).
	 *
	 * @var array<string, bool>
	 */
	public array $refuse = array();

	/**
	 * Every request: [method, url, token].
	 *
	 * @var list<array{0:string, 1:string, 2:string}>
	 */
	public array $calls = array();

	private int $next_op = 1;

	/**
	 * pre_http_request filter.
	 *
	 * @param mixed                $pre  Short-circuit value.
	 * @param array<string, mixed> $args Request arguments.
	 * @param string               $url  URL.
	 * @return array<string, mixed>|\WP_Error
	 */
	public function __invoke( $pre, $args, $url ) {
		if ( ! str_starts_with( (string) $url, 'https://api.cloudflare.com/' ) ) {
			return $pre;
		}
		$token         = substr( (string) ( $args['headers']['Authorization'] ?? '' ), 7 );
		$this->calls[] = array( (string) $args['method'], (string) $url, $token );
		$fault         = array_shift( $this->faults );
		if ( 'timeout' === $fault ) {
			return new \WP_Error( 'http_request_failed', 'cURL error 28: Operation timed out after 20001 milliseconds' );
		}
		if ( 'rate_limited' === $fault ) {
			return self::reply( 429, array( 'success' => false, 'errors' => array( array( 'message' => 'rate limited' ) ) ), array( 'retry-after' => '900' ) );
		}
		if ( 'malformed' === $fault ) {
			return array(
				'headers'  => array(),
				'body'     => '<html>502 Bad Gateway',
				'response' => array( 'code' => 200, 'message' => 'OK' ),
				'cookies'  => array(),
				'filename' => null,
			);
		}
		if ( 'server_error' === $fault ) {
			return self::reply( 500, array( 'success' => false, 'errors' => array( array( 'message' => 'internal error' ) ) ) );
		}
		if ( empty( $this->tokens[ $token ] ) ) {
			return self::reply( 403, array( 'success' => false, 'errors' => array( array( 'code' => 10000, 'message' => 'Authentication error' ) ) ) );
		}
		if ( preg_match( '#/accounts/([^/]+)/rules/lists/bulk_operations/([^/]+)$#', (string) $url, $m ) ) {
			$op = $this->ops[ $m[2] ] ?? null;
			if ( null === $op ) {
				return self::reply( 404, array( 'success' => false, 'errors' => array( array( 'message' => 'not found' ) ) ) );
			}
			if ( $op['polls'] > 0 ) {
				--$this->ops[ $m[2] ]['polls'];
				return self::reply( 200, array( 'success' => true, 'result' => array( 'status' => 'running' ) ) );
			}
			if ( $op['fail'] ) {
				return self::reply( 200, array( 'success' => true, 'result' => array( 'status' => 'failed', 'error' => 'item limit reached' ) ) );
			}
			$this->lists[ $op['key'] ] = $op['items'];
			return self::reply( 200, array( 'success' => true, 'result' => array( 'status' => 'completed' ) ) );
		}
		if ( preg_match( '#/accounts/([^/]+)/rules/lists/([^/]+)/items$#', (string) $url, $m ) && 'PUT' === $args['method'] ) {
			$key = $m[1] . '/' . $m[2];
			if ( ! empty( $this->refuse[ $key ] ) ) {
				return self::reply( 400, array( 'success' => false, 'errors' => array( array( 'message' => 'list not found' ) ) ) );
			}
			$items            = array_column( (array) json_decode( (string) $args['body'], true ), 'ip' );
			$id               = 'op' . $this->next_op++;
			$this->ops[ $id ] = array(
				'key'   => $key,
				'items' => $items,
				'polls' => $this->polls,
				'fail'  => $this->fail_ops,
			);
			if ( 'timeout_after_apply' === $fault ) {
				// Cloudflare took it; the answer never arrived.
				$this->lists[ $key ] = $items;
				return new \WP_Error( 'http_request_failed', 'cURL error 28: Operation timed out' );
			}
			return self::reply( 200, array( 'success' => true, 'result' => array( 'operation_id' => $id ) ) );
		}
		return self::reply( 200, array( 'success' => true, 'result' => array( 'kind' => 'ip', 'name' => 'blocked', 'num_items' => 0 ) ) );
	}

	/**
	 * An HTTP response as WordPress's HTTP API returns it.
	 *
	 * @param int                   $code    Status.
	 * @param array<string, mixed>  $body    JSON body.
	 * @param array<string, string> $headers Headers.
	 * @return array<string, mixed>
	 */
	private static function reply( int $code, array $body, array $headers = array() ): array {
		return array(
			'headers'  => $headers,
			'body'     => (string) wp_json_encode( $body ),
			'response' => array(
				'code'    => $code,
				'message' => '',
			),
			'cookies'  => array(),
			'filename' => null,
		);
	}
}

/**
 * Review 5 (P0): timeouts, 429 responses, malformed answers, operations that
 * take long or fail, credential rotation and expiry, and destination changes.
 * In every case the plugin reports the problem honestly, never claims a list
 * is up to date before Cloudflare confirms it, and ends with exactly the
 * effective policy at Cloudflare once the API behaves again.
 */
final class CloudflareContractTest extends \WP_UnitTestCase {

	private FakeCloudflare $cf;

	private CloudflareSync $sync;

	private string $data = '';

	private const ACCOUNT = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

	public function private_dir(): string {
		return $this->data;
	}

	public function set_up(): void {
		parent::set_up();
		$this->data = sys_get_temp_dir() . '/ss-cf-' . wp_generate_password( 6, false );
		add_filter( 'sentinel_shield_data_dir', array( $this, 'private_dir' ) );
		$_SERVER['DOCUMENT_ROOT'] = ABSPATH;
		DataDir::recheck();
		$c = Plugin::instance()->container();
		global $wpdb;
		$wpdb->query( $wpdb->prepare( 'DELETE FROM %i', $c->get( BlockRepository::class )->table() ) );
		$c->get( RuleCache::class )->flush();
		$c->get( BlockRepository::class )->add( 'block', Cidr::parse( '203.0.113.0/30' ), 'manual', 'manual' );
		$c->get( BlockRepository::class )->add( 'block', Cidr::parse( '198.51.100.7' ), 'manual', 'manual' );
		$this->settings( 'list-one' );
		$this->sync = $c->get( CloudflareSync::class );
		$this->sync->set_token( 'token-a' );
		$this->cf = new FakeCloudflare();
		add_filter( 'pre_http_request', $this->cf, 10, 3 );
		add_filter( 'sentinel_shield_cloudflare_poll_delay', '__return_zero' );
	}

	public function tear_down(): void {
		remove_filter( 'pre_http_request', $this->cf, 10 );
		remove_filter( 'sentinel_shield_cloudflare_poll_delay', '__return_zero' );
		remove_filter( 'sentinel_shield_data_dir', array( $this, 'private_dir' ) );
		EarlyGate::delete_files();
		exec( 'rm -rf ' . escapeshellarg( $this->data ) ); // Dot files (.htaccess) included.
		foreach ( array( CloudflareSync::TOKEN, CloudflareSync::STATE, EarlyGate::STATE, Settings::OPTION, DataDir::OPTION, DataDir::ROOT ) as $option ) {
			delete_site_option( $option );
		}
		wp_clear_scheduled_hook( CloudflareSync::CRON );
		wp_clear_scheduled_hook( CloudflareSync::CHECK );
		unset( $_SERVER['DOCUMENT_ROOT'] );
		Plugin::instance()->container()->get( Settings::class )->refresh();
		parent::tear_down();
	}

	/**
	 * Saves settings pointing at a list.
	 *
	 * @param string $list List ID.
	 */
	private function settings( string $list ): void {
		update_site_option(
			Settings::OPTION,
			array(
				'general'    => array( 'test_mode' => false ),
				'firewall'   => array( 'early_gate' => 'mu_plugin' ),
				'cloudflare' => array(
					'sync'       => true,
					'account_id' => self::ACCOUNT,
					'list_id'    => $list,
				),
			)
		);
		Plugin::instance()->container()->get( Settings::class )->refresh();
		Plugin::instance()->container()->get( EarlyGate::class )->rebuild();
	}

	/**
	 * Makes the stored state look $seconds older, as if that much time passed.
	 *
	 * @param int $seconds Seconds.
	 */
	private static function later( int $seconds ): void {
		$state = CloudflareSync::state();
		foreach ( array( 'time', 'retry_at' ) as $key ) {
			if ( ! empty( $state[ $key ] ) ) {
				$state[ $key ] -= $seconds;
			}
		}
		foreach ( (array) ( $state['retired'] ?? array() ) as $i => $old ) {
			foreach ( array( 'time', 'retry_at' ) as $key ) {
				if ( ! empty( $old[ $key ] ) ) {
					$state['retired'][ $i ][ $key ] -= $seconds;
				}
			}
		}
		update_site_option( CloudflareSync::STATE, $state );
	}

	/**
	 * Runs the next scheduled sync or check, as WP-Cron would once its time
	 * comes; returns the hook that ran and how long after now it was due.
	 *
	 * @return array{0:string, 1:int}
	 */
	private function cron(): array {
		$due = array_filter(
			array(
				CloudflareSync::CRON  => wp_next_scheduled( CloudflareSync::CRON ),
				CloudflareSync::CHECK => wp_next_scheduled( CloudflareSync::CHECK ),
			)
		);
		$this->assertNotEmpty( $due, 'something is scheduled to finish the job' );
		asort( $due );
		$hook  = (string) array_key_first( $due );
		$delay = max( 0, (int) $due[ $hook ] - time() );
		wp_clear_scheduled_hook( $hook );
		self::later( $delay );
		do_action( $hook );
		return array( $hook, $delay );
	}

	/**
	 * Runs scheduled work until Cloudflare holds $items and the state says so.
	 *
	 * @param list<string> $items Expected list content.
	 * @param string       $key   account/list.
	 */
	private function converges( array $items, string $key = self::ACCOUNT . '/list-one', int $max = 40 ): void {
		for ( $i = 0; $i < $max; $i++ ) {
			$state = CloudflareSync::state();
			if ( in_array( $state['status'] ?? '', array( 'active', 'empty' ), true ) && empty( $state['retired'] ) ) {
				break;
			}
			$this->cron();
		}
		$state = CloudflareSync::state();
		$this->assertContains( $state['status'] ?? '', array( 'active', 'empty' ), 'confirmed by Cloudflare: ' . wp_json_encode( $state ) );
		$this->assertSame( array(), (array) ( $state['retired'] ?? array() ), 'no list left to empty' );
		$held = $this->cf->lists[ $key ] ?? array();
		sort( $held );
		sort( $items );
		$this->assertSame( $items, $held, 'Cloudflare holds exactly the policy' );
		$this->assertSame( '', (string) ( $state['error'] ?? '' ) );
	}

	private const POLICY = array( '203.0.113.0/30', '198.51.100.7' );

	public function test_a_timeout_is_reported_and_retried(): void {
		$this->cf->faults = array( 'timeout' );
		$state            = $this->sync->sync();
		$this->assertSame( 'failed', $state['status'] );
		$this->assertStringContainsString( 'timed out', $state['error'] );
		$this->assertTrue( $this->sync->manages_items(), 'the list may hold items: not forgotten' );
		$this->assertGreaterThanOrEqual( time() + CloudflareSync::INTERVAL, (int) wp_next_scheduled( CloudflareSync::CRON ), 'retried after the interval' );
		$this->converges( self::POLICY );
	}

	public function test_an_upload_applied_but_unanswered_is_sent_again(): void {
		$this->cf->faults = array( 'timeout_after_apply' );
		$this->assertSame( 'failed', $this->sync->sync()['status'], 'not known to be applied' );
		$this->converges( self::POLICY );
		$this->assertCount( 2, array_filter( $this->cf->calls, static fn( array $c ): bool => 'PUT' === $c[0] ), 'uploaded again (a replace is idempotent)' );
	}

	public function test_rate_limiting_waits_as_long_as_cloudflare_asks(): void {
		$this->cf->faults = array( 'rate_limited' );
		$state            = $this->sync->sync();
		$this->assertSame( 'failed', $state['status'] );
		$this->assertStringContainsString( '900 seconds', $state['error'] );
		$this->assertGreaterThanOrEqual( time() + 900, (int) wp_next_scheduled( CloudflareSync::CRON ), 'Retry-After respected' );
		$calls = count( $this->cf->calls );
		$this->sync->sync();
		$this->assertCount( $calls, $this->cf->calls, 'an early scheduled sync does not call Cloudflare again' );
		[ , $delay ] = $this->cron();
		$this->assertGreaterThanOrEqual( 899, $delay );
		$this->converges( self::POLICY );
	}

	public function test_malformed_and_server_error_answers_are_failures(): void {
		$this->cf->faults = array( 'malformed' );
		$state            = $this->sync->sync();
		$this->assertSame( 'failed', $state['status'] );
		$this->assertStringContainsString( 'unexpected response', $state['error'] );
		self::later( CloudflareSync::INTERVAL );
		$this->cf->faults = array( 'server_error' );
		$this->assertStringContainsString( '500', $this->sync->sync()['error'] );
		$this->converges( self::POLICY );
	}

	public function test_slow_unconfirmed_and_failed_operations_are_redone(): void {
		// Takes longer than the plugin waits: unknown, then uploaded again.
		$this->cf->polls = 25;
		$this->assertSame( 'applying', $this->sync->sync()['status'] );
		for ( $i = 0; $i < 20; $i++ ) {
			$this->assertSame( CloudflareSync::CHECK, $this->cron()[0] );
		}
		$this->assertSame( 'unknown', CloudflareSync::state()['status'] );
		$this->assertTrue( $this->sync->manages_items() );
		$this->cf->polls = 2;
		$this->converges( self::POLICY );

		// Cloudflare reports the operation failed: retried.
		Plugin::instance()->container()->get( BlockRepository::class )->add( 'block', Cidr::parse( '192.0.2.1' ), 'manual', 'manual' );
		Plugin::instance()->container()->get( EarlyGate::class )->rebuild();
		$this->cf->fail_ops = true;
		$this->cf->polls    = 0;
		self::later( CloudflareSync::INTERVAL );
		$this->sync->sync();
		$this->cron();
		$this->assertSame( 'failed', CloudflareSync::state()['status'] );
		$this->assertStringContainsString( 'item limit', CloudflareSync::state()['error'] );
		$this->cf->fail_ops = false;
		$this->converges( array( '203.0.113.0/30', '198.51.100.7', '192.0.2.1' ) );
	}

	public function test_a_policy_change_while_applying_waits_for_the_first_operation(): void {
		$this->cf->polls = 3;
		$this->sync->sync();
		Plugin::instance()->container()->get( BlockRepository::class )->add( 'block', Cidr::parse( '192.0.2.1' ), 'manual', 'manual' );
		Plugin::instance()->container()->get( EarlyGate::class )->rebuild();
		$puts = count( array_filter( $this->cf->calls, static fn( array $c ): bool => 'PUT' === $c[0] ) );
		$this->sync->sync();
		$this->assertCount( $puts, array_filter( $this->cf->calls, static fn( array $c ): bool => 'PUT' === $c[0] ), 'no overlapping upload' );
		$this->converges( self::POLICY );
		self::later( CloudflareSync::INTERVAL );
		$this->sync->sync();
		$this->converges( array( '203.0.113.0/30', '198.51.100.7', '192.0.2.1' ) );
	}

	public function test_credential_rotation_and_expired_credentials(): void {
		$this->sync->sync();
		$this->converges( self::POLICY );

		// Rotated: the new token is used from the next call on; the old one may be revoked.
		$this->cf->tokens = array( 'token-b' => true );
		$this->assertTrue( $this->sync->set_token( 'token-b' ) );
		Plugin::instance()->container()->get( BlockRepository::class )->add( 'block', Cidr::parse( '192.0.2.1' ), 'manual', 'manual' );
		Plugin::instance()->container()->get( EarlyGate::class )->rebuild();
		self::later( CloudflareSync::INTERVAL );
		$this->sync->sync();
		$this->converges( array( '203.0.113.0/30', '198.51.100.7', '192.0.2.1' ) );
		$this->assertSame( 'token-b', end( $this->cf->calls )[2] );

		// Expired or revoked: reported, and the token cannot be removed while the list holds items.
		$this->cf->tokens = array();
		Plugin::instance()->container()->get( BlockRepository::class )->add( 'block', Cidr::parse( '192.0.2.2' ), 'manual', 'manual' );
		Plugin::instance()->container()->get( EarlyGate::class )->rebuild();
		self::later( CloudflareSync::INTERVAL );
		$state = $this->sync->sync();
		$this->assertSame( 'failed', $state['status'] );
		$this->assertStringContainsString( 'Authentication error', $state['error'] );
		$this->assertIsString( $this->sync->set_token( '' ), 'kept: without it the list could never be emptied' );
		$this->assertTrue( $this->sync->has_token() );

		// A new valid token: everything catches up.
		$this->cf->tokens = array( 'token-c' => true );
		$this->sync->set_token( 'token-c' );
		$this->converges( array( '203.0.113.0/30', '198.51.100.7', '192.0.2.1', '192.0.2.2' ) );
		$this->assertTrue( $this->sync->set_token( '' ), 'removed once the list is confirmed empty' );
		$this->assertSame( array(), $this->cf->lists[ self::ACCOUNT . '/list-one' ] );
		$this->assertFalse( $this->sync->has_token() );
	}

	public function test_a_new_destination_empties_the_old_list_even_through_failures(): void {
		$this->sync->sync();
		$this->converges( self::POLICY );

		$this->settings( 'list-two' );
		$this->cf->refuse = array( self::ACCOUNT . '/list-one' => true );
		$this->sync->settings_saved();
		$this->cron();
		$state = CloudflareSync::state();
		$this->assertSame( 'list-one', $state['retired'][0]['list'], 'the old list is remembered until it is empty' );
		$this->assertSame( 'failed', $state['retired'][0]['status'] );
		$this->assertEqualsCanonicalizing( self::POLICY, $this->cf->lists[ self::ACCOUNT . '/list-one' ], 'still holds the old policy' );

		$this->cf->refuse = array();
		$this->converges( self::POLICY, self::ACCOUNT . '/list-two' );
		$this->assertSame( array(), $this->cf->lists[ self::ACCOUNT . '/list-one' ], 'the old list was emptied in the end' );
	}

	/**
	 * A worker that dies right after Cloudflare took the upload leaves a state
	 * that admits the list content is unknown: it is retried, and switching
	 * sync off still empties the list (no blocks stranded at Cloudflare).
	 */
	public function test_a_worker_killed_after_the_upload_strands_nothing(): void {
		$this->cf->polls = 0;
		$die             = static function ( string $step ): void {
			if ( 'cloudflare:sent' === $step ) {
				throw new \RuntimeException( 'worker killed' );
			}
		};
		add_action( 'sentinel_shield_checkpoint', $die );
		try {
			$this->sync->sync();
			$this->fail( 'should have died' );
		} catch ( \RuntimeException $e ) {
			$this->assertSame( 'worker killed', $e->getMessage() );
		} finally {
			remove_action( 'sentinel_shield_checkpoint', $die );
		}
		// Cloudflare applied the upload meanwhile.
		foreach ( $this->cf->ops as $op ) {
			$this->cf->lists[ $op['key'] ] = $op['items'];
		}
		$this->assertNotEmpty( $this->cf->lists[ self::ACCOUNT . '/list-one' ], 'Cloudflare holds the policy' );
		$state = CloudflareSync::state();
		$this->assertSame( 'unknown', $state['status'] ?? '', 'no claim the list is known' );
		$this->assertNotFalse( wp_next_scheduled( CloudflareSync::CRON ), 'and a sync is due to find out' );
		$this->assertTrue( $this->sync->manages_items() );

		// Switched off now: the list is emptied, not forgotten.
		update_site_option( Settings::OPTION, array( 'cloudflare' => array( 'sync' => false, 'account_id' => self::ACCOUNT, 'list_id' => 'list-one' ) ) );
		Plugin::instance()->container()->get( Settings::class )->refresh();
		$this->sync->settings_saved();
		$this->converges( array() );
	}
}
