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
use SentinelShield\Tests\Fakes\FakeCloudflare;
use SentinelShield\Tests\Fakes\OtherWorker;

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

	/**
	 * Review 6 (Cloudflare concurrency): while another worker is updating the
	 * list, scheduled work waits its turn and explicit actions say so; nothing
	 * reaches Cloudflare and nothing changes the state.
	 */
	public function test_one_update_at_a_time(): void {
		$other = new OtherWorker();
		$this->assertTrue( $other->hold( 'cloudflare_sync' ), 'another worker is syncing' );
		add_filter( 'sentinel_shield_cloudflare_lock_wait', '__return_zero' );
		try {
			$before = CloudflareSync::state();
			wp_clear_scheduled_hook( CloudflareSync::CRON );
			$this->sync->sync();
			$this->assertSame( array(), $this->cf->calls, 'a scheduled sync does not touch the list meanwhile' );
			$this->assertLessThanOrEqual( time() + 30, (int) wp_next_scheduled( CloudflareSync::CRON ), 'and tries again shortly' );

			$forced = $this->sync->sync( true );
			$this->assertFalse( $forced['ok'] );
			$this->assertStringContainsString( 'still running', (string) $forced['error'] );

			wp_clear_scheduled_hook( CloudflareSync::CHECK );
			$this->sync->check_operation();
			$this->assertNotFalse( wp_next_scheduled( CloudflareSync::CHECK ), 'the confirmation check comes back' );
			$this->assertFalse( $this->sync->clear_remote( 'test' ), 'emptying is not claimed' );
			$this->assertSame( array(), $this->cf->calls );
			$this->assertSame( $before, CloudflareSync::state(), 'state untouched' );
		} finally {
			remove_filter( 'sentinel_shield_cloudflare_lock_wait', '__return_zero' );
			$other->close();
		}
		$this->sync->sync( true );
		$this->converges( self::POLICY );
	}

	/**
	 * A worker that lost the lock after uploading records nothing more; the
	 * intent it recorded first makes the next holder upload again.
	 */
	public function test_an_upload_whose_lock_was_lost_is_redone_by_the_next_holder(): void {
		$other = new OtherWorker();
		$steal = static function ( string $step ) use ( $other ): void {
			if ( 'cloudflare:sent' === $step ) {
				$other->steal( 'cloudflare_sync' );
			}
		};
		add_action( 'sentinel_shield_checkpoint', $steal );
		try {
			$this->sync->sync( true );
		} finally {
			remove_action( 'sentinel_shield_checkpoint', $steal );
		}
		$state = CloudflareSync::state();
		$this->assertSame( 'unknown', $state['status'], 'only the intent is recorded: not claimed as applying or active' );
		$this->assertTrue( $this->sync->manages_items() );
		$other->close();
		$this->converges( self::POLICY );
	}

	/**
	 * An answer about a bulk operation that arrives after a newer upload
	 * replaced it never overwrites the newer state.
	 */
	public function test_a_stale_answer_never_overwrites_newer_state(): void {
		$this->cf->polls = 5;
		$this->sync->sync( true );
		$old = CloudflareSync::state();
		$this->assertSame( 'applying', $old['status'] );
		$this->cf->ops[ $old['operation'] ]['polls'] = 0; // Cloudflare answers "completed" for the old operation.

		// While the answer travels, another worker takes over and uploads anew.
		$other = new OtherWorker();
		$newer = array(
			'operation' => 'op-newer',
			'want'      => 'policy',
			'status'    => 'applying',
			'items'     => 'newer',
		) + $old;
		$takeover = static function ( string $step ) use ( $other, $newer ): void {
			if ( 'cloudflare:polled' === $step ) {
				$other->steal( 'cloudflare_sync' );
				update_site_option( CloudflareSync::STATE, $newer );
			}
		};
		add_action( 'sentinel_shield_checkpoint', $takeover );
		try {
			$this->sync->check_operation();
		} finally {
			remove_action( 'sentinel_shield_checkpoint', $takeover );
			$other->close();
		}
		$this->assertSame( $newer, CloudflareSync::state(), 'the late "completed" did not mark the newer upload active' );

		// The same rule, without a lost lock: answers apply only to the operation they are about.
		$dest  = array(
			'account' => self::ACCOUNT,
			'list'    => 'list-one',
		);
		$state = array(
			'dest'      => $dest,
			'status'    => 'applying',
			'operation' => 'op-b',
			'retired'   => array(
				array(
					'account'   => self::ACCOUNT,
					'list'      => 'list-old',
					'status'    => 'applying',
					'operation' => 'op-b',
				),
			),
		);
		$late  = array( self::ACCOUNT . '/list-one/op-a' => array( 'status' => 'active' ) );
		$this->assertSame( $state, CloudflareSync::apply_answers( $state, $late ), 'an answer about op-a changes nothing' );
		$done = CloudflareSync::apply_answers( $state, array( self::ACCOUNT . '/list-old/op-b' => array( 'status' => 'empty' ) ) );
		$this->assertSame( 'applying', $done['status'], 'the same operation ID on another list is another operation' );
		$this->assertSame( array(), $done['retired'], 'the old list, confirmed empty, is forgotten' );
	}
}
