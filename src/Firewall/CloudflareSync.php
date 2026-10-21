<?php
/**
 * Keeps a Cloudflare IP list in step with the blocklist.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Firewall;

use SentinelShield\Net\Cidr;
use SentinelShield\Net\RangeMath;
use SentinelShield\Net\IpRangeSet;
use SentinelShield\Settings;
use SentinelShield\Support\Mutex;
use SentinelShield\TwoFactor\SecretBox;

defined( 'ABSPATH' ) || exit;

/**
 * Blocking at Cloudflare stops attackers before their requests reach the
 * server at all, including static files. Sentinel Shield replaces the items of
 * one Cloudflare account IP list with its enforced block rules (manual rules
 * and lockouts) whenever they change; a Cloudflare WAF custom rule such as
 * `ip.src in $sentinel_shield_block` with the action Block does the rest.
 *
 * The API token needs only "Account Filter Lists: Edit". It is stored
 * encrypted with keys from wp-config.php and never included in settings exports.
 *
 * Concurrency: scheduled syncs, confirmation checks, Sync now, WP-CLI,
 * settings changes, token removal and deactivation all change one state
 * record, and each waits on Cloudflare in between. They run one at a time
 * under the cloudflare_sync lock (scheduled work does not wait for it and is
 * rescheduled; explicit actions wait up to LOCK_WAIT seconds). Every state
 * write first confirms the lock is still held (save()); a worker that lost it
 * writes nothing more, and the intent recorded before each upload makes the
 * next holder send it again. Answers about a bulk operation are applied only
 * to the state that still names that operation, so a slow or stale answer
 * can never overwrite a newer upload's state.
 */
final class CloudflareSync {

	public const CRON      = 'sentinel_shield_cloudflare_sync';
	public const CHECK     = 'sentinel_shield_cloudflare_check';
	public const TOKEN     = 'sentinel_shield_cf_token';
	public const STATE     = 'sentinel_shield_cf_state';
	public const MAX_ITEMS = 10000;
	public const INTERVAL  = 300;
	public const LOCK_WAIT = 20;
	private const LOCK     = 'cloudflare_sync';
	private const API      = 'https://api.cloudflare.com/client/v4/accounts/%s/rules/lists/%s';
	private const BULK     = 'https://api.cloudflare.com/client/v4/accounts/%s/rules/lists/bulk_operations/%s';

	/**
	 * Constructor.
	 *
	 * @param Settings  $settings Settings.
	 * @param SecretBox $box      Encryption for the token.
	 * @param EarlyGate $gate     Source of the enforced block rules.
	 */
	public function __construct( private Settings $settings, private SecretBox $box, private EarlyGate $gate ) {}

	/**
	 * Hooks syncing to blocklist changes.
	 */
	public function register(): void {
		add_action( 'sentinel_shield_blocklist_changed', array( $this, 'schedule' ) );
		add_action( self::CRON, array( $this, 'cron_sync' ) );
		add_action( self::CHECK, array( $this, 'cron_check' ) );
		add_action( 'sentinel_shield_settings_saved', array( $this, 'settings_saved' ) );
	}

	/**
	 * Scheduled sync (an action callback returns nothing).
	 */
	public function cron_sync(): void {
		$this->sync();
	}

	/**
	 * Scheduled confirmation check.
	 */
	public function cron_check(): void {
		$this->check_operation();
	}

	/**
	 * Whether syncing is switched on and configured.
	 */
	public function enabled(): bool {
		return (bool) $this->settings->get( 'cloudflare.sync', false ) && '' !== $this->account() && '' !== $this->list() && '' !== $this->token();
	}

	/**
	 * Schedules a sync: half a minute from now, so changes in a burst are synced
	 * once, and at most once every INTERVAL seconds, so short lockouts starting
	 * and ending do not republish the whole list each time.
	 */
	public function schedule(): void {
		if ( $this->enabled() && ! wp_next_scheduled( self::CRON ) ) {
			wp_schedule_single_event( max( time() + 30, (int) ( self::state()['time'] ?? 0 ) + self::INTERVAL ), self::CRON );
		}
	}

	/**
	 * Stores the API token (encrypted), or removes it with ''. Before the token
	 * is removed, the list it manages is emptied: without the token, Sentinel
	 * Shield could never empty it again.
	 *
	 * @param string $token Token.
	 * @return true|string True, or why the token was kept.
	 */
	public function set_token( string $token ): bool|string {
		$token = trim( $token );
		if ( '' !== $token ) {
			update_site_option( self::TOKEN, $this->box->seal( $token ) );
			return true;
		}
		if ( $this->manages_items() && '' !== $this->token() ) {
			$this->clear_remote( __( 'API token removed', 'sentinel-shield' ), true );
			if ( 'empty' !== ( self::state()['status'] ?? '' ) ) {
				return __( 'The token was kept: the Cloudflare list it manages could not be confirmed empty, and without the token it could not be emptied later. Empty the list (or delete the WAF rule) in Cloudflare, or try again.', 'sentinel-shield' );
			}
		}
		delete_site_option( self::TOKEN );
		return true;
	}

	/**
	 * Whether a token is stored.
	 */
	public function has_token(): bool {
		return '' !== $this->token();
	}

	/**
	 * Last sync result: time, ok, count, error.
	 *
	 * @return array<string, mixed>
	 */
	public static function state(): array {
		$state = get_site_option( self::STATE );
		return is_array( $state ) ? $state : array();
	}

	/**
	 * Checks that the list exists and the token can read it.
	 *
	 * @return array{ok:bool, message:string}
	 */
	public function test(): array {
		$response = $this->request( 'GET', '' );
		if ( is_wp_error( $response ) ) {
			return array(
				'ok'      => false,
				'message' => $response->get_error_message(),
			);
		}
		$list = (array) ( $response['result'] ?? array() );
		if ( 'ip' !== ( $list['kind'] ?? '' ) ) {
			return array(
				'ok'      => false,
				'message' => __( 'That list is not an IP list. Create a list of type "IP" under Manage Account → Configurations → Lists.', 'sentinel-shield' ),
			);
		}
		return array(
			'ok'      => true,
			/* translators: 1: list name, 2: number of items. */
			'message' => sprintf( __( 'Connected to the list "%1$s" (%2$d items).', 'sentinel-shield' ), (string) ( $list['name'] ?? '' ), (int) ( $list['num_items'] ?? 0 ) ),
		);
	}

	/**
	 * Replaces the list's items with the effective block policy (the same one
	 * the early firewall and the server files use; empty while WordPress does
	 * not enforce blocks), then follows Cloudflare's bulk operation until it
	 * reports the list as updated.
	 *
	 * Uploading and emptying share one state: status is applying (sent, not yet
	 * confirmed), active or empty (confirmed by Cloudflare), failed, or unknown
	 * (never confirmed); failed and unknown are retried. A list the settings no
	 * longer point at is emptied before it is forgotten (see retire()).
	 *
	 * Scheduled syncs skip the upload when Cloudflare already has the same list,
	 * wait while its previous bulk operation is still running, and keep to one
	 * upload per INTERVAL (an emptied policy is sent at once). $force (Sync now,
	 * WP-CLI) always uploads.
	 *
	 * @param bool $force Upload even if unchanged or recent.
	 * @return array<string, mixed> The new state.
	 */
	public function sync( bool $force = false ): array {
		return $this->locked(
			$force ? self::lock_wait() : 0,
			fn(): array => $this->sync_locked( $force ),
			function () use ( $force ): array {
				if ( ! $force ) {
					// Another update is running: try again shortly.
					if ( ! wp_next_scheduled( self::CRON ) ) {
						wp_schedule_single_event( time() + 30, self::CRON );
					}
					return self::state();
				}
				return array(
					'ok'    => false,
					'error' => __( 'Another update of the Cloudflare list is still running; try again in a minute.', 'sentinel-shield' ),
				) + self::state();
			}
		);
	}

	/**
	 * Body of sync(), under the lock.
	 *
	 * @param bool $force Upload even if unchanged or recent.
	 * @return array<string, mixed> The new state.
	 */
	private function sync_locked( bool $force ): array {
		$this->retry_retired();
		if ( ! $this->enabled() ) {
			// Switched off with items still there (an earlier clear failed): keep trying.
			if ( $this->manages_items() && '' !== $this->token() && ! $this->settings->get( 'cloudflare.sync', false ) ) {
				$this->clear_remote( __( 'sync switched off', 'sentinel-shield' ) );
			}
			return self::state();
		}
		$prior = self::state();
		$dest  = $this->destination();
		if ( ! empty( $prior['dest'] ) && $prior['dest'] !== $dest ) {
			$this->retire( (array) $prior['dest'], $prior );
			$prior = self::state();
		}
		$data  = $this->gate->published_policy() ?? $this->gate->compile();
		$conv  = self::items( $data['blocked'], (string) $this->settings->get( 'cloudflare.ipv6', 'skip' ), $data['allow_set'] );
		$gen   = (int) ( ( (array) get_site_option( EarlyGate::STATE, array() ) )['generation'] ?? 0 );
		$hash  = md5( implode( ',', $conv['items'] ) );
		$empty = ! $conv['items'];
		if ( ! $force ) {
			$status = (string) ( $prior['status'] ?? '' );
			$same   = ( $prior['dest'] ?? null ) === $dest && ( $prior['items'] ?? '' ) === $hash;
			if ( $same && in_array( $status, array( 'active', 'applying', 'empty' ), true ) ) {
				// Same list already there (or on its way): nothing to upload.
				$prior['generation'] = $gen;
				$this->save( $prior );
				return $prior;
			}
			$wait = 0;
			if ( 'applying' === $status ) {
				$wait = 30;
			} elseif ( time() < (int) ( $prior['retry_at'] ?? 0 ) ) {
				$wait = (int) $prior['retry_at'] - time(); // Cloudflare asked us to slow down.
			} elseif ( ! $empty && ! empty( $prior['ok'] ) && time() < (int) ( $prior['time'] ?? 0 ) + self::INTERVAL ) {
				$wait = (int) $prior['time'] + self::INTERVAL - time();
			}
			if ( $wait > 0 ) {
				if ( ! wp_next_scheduled( self::CRON ) ) {
					wp_schedule_single_event( time() + $wait, self::CRON );
				}
				return $prior;
			}
		}
		if ( ! $this->intend( $dest, $empty ? 'empty' : 'policy' ) ) {
			return self::state(); // The lock was lost: the new holder syncs.
		}
		$sent = $this->send( $dest, $conv['items'] );
		do_action( 'sentinel_shield_checkpoint', 'cloudflare:sent' );
		$state = array(
			'time'       => time(),
			'ok'         => $sent['ok'],
			'dest'       => $dest,
			'want'       => $empty ? 'empty' : 'policy',
			'count'      => count( $conv['items'] ),
			'skipped'    => $conv['skipped'],
			'expanded'   => $conv['expanded'],
			'generation' => $gen,
			'status'     => $sent['status'],
			'operation'  => $sent['operation'],
			'checks'     => 0,
			'items'      => $sent['ok'] ? $hash : '',
			'error'      => $sent['error'],
			'retry_at'   => $sent['retry_at'],
			'retired'    => (array) ( self::state()['retired'] ?? array() ),
		);
		if ( ! $this->save( $state ) ) {
			return self::state();
		}
		$this->follow_up( $state );
		return $state;
	}

	/**
	 * Asks Cloudflare whether pending bulk operations finished: the current
	 * list's and those of lists being emptied before they are forgotten.
	 *
	 * @return array<string, mixed> The state afterwards.
	 */
	public function check_operation(): array {
		return $this->locked(
			0,
			fn(): array => $this->check_locked(),
			function (): array {
				if ( ! wp_next_scheduled( self::CHECK ) ) {
					wp_schedule_single_event( time() + 15, self::CHECK );
				}
				return self::state();
			}
		);
	}

	/**
	 * Body of check_operation(), under the lock. Cloudflare's answers are
	 * matched to the state as it is after asking, by operation ID: an answer
	 * about an operation the state no longer names changes nothing.
	 *
	 * @return array<string, mixed> The state afterwards.
	 */
	private function check_locked(): array {
		$state   = self::state();
		$answers = array();
		if ( 'applying' === ( $state['status'] ?? '' ) && '' !== (string) ( $state['operation'] ?? '' ) ) {
			$answers[ self::operation_key( (array) ( $state['dest'] ?? array() ), $state ) ] = $this->poll( $state, (string) ( $state['want'] ?? 'policy' ) );
		}
		foreach ( (array) ( $state['retired'] ?? array() ) as $old ) {
			if ( 'applying' === ( $old['status'] ?? '' ) && '' !== (string) ( $old['operation'] ?? '' ) ) {
				$answers[ self::operation_key( $old, $old ) ] = $this->poll( $old, 'empty' );
			}
		}
		do_action( 'sentinel_shield_checkpoint', 'cloudflare:polled' );
		$state = self::apply_answers( self::state(), $answers );
		if ( ! $this->save( $state ) ) {
			return self::state();
		}
		$this->follow_up( $state );
		return $state;
	}

	/**
	 * Applies answers about bulk operations (operation_key() => changed
	 * fields) to a state: only to an entry still applying that operation on
	 * that list. Confirmed empty retired lists are forgotten.
	 *
	 * @param array<string, mixed>                $state   State.
	 * @param array<string, array<string, mixed>> $answers Answers by operation key.
	 * @return array<string, mixed>
	 */
	public static function apply_answers( array $state, array $answers ): array {
		$current = self::operation_key( (array) ( $state['dest'] ?? array() ), $state );
		if ( '' !== (string) ( $state['operation'] ?? '' ) && isset( $answers[ $current ] ) && 'applying' === ( $state['status'] ?? '' ) ) {
			$state = array_merge( $state, $answers[ $current ] );
		}
		$retired = array();
		foreach ( (array) ( $state['retired'] ?? array() ) as $old ) {
			$key = self::operation_key( $old, $old );
			if ( '' !== (string) ( $old['operation'] ?? '' ) && isset( $answers[ $key ] ) && 'applying' === ( $old['status'] ?? '' ) ) {
				$old = array_merge( $old, $answers[ $key ] );
			}
			if ( 'empty' !== ( $old['status'] ?? '' ) ) {
				$retired[] = $old;
			}
		}
		$state['retired'] = $retired;
		return $state;
	}

	/**
	 * Identifies one bulk operation: account, list and operation ID
	 * (operation IDs are only unique within an account).
	 *
	 * @param array<string, mixed> $dest  account, list.
	 * @param array<string, mixed> $entry State or retired entry with operation.
	 */
	private static function operation_key( array $dest, array $entry ): string {
		return (string) ( $dest['account'] ?? '' ) . '/' . (string) ( $dest['list'] ?? '' ) . '/' . (string) ( $entry['operation'] ?? '' );
	}

	/**
	 * Empties the managed Cloudflare list (sync switched off, token removed,
	 * plugin deactivated), so no block stays active at the edge without
	 * Sentinel Shield managing it. The list counts as empty only once
	 * Cloudflare confirms the bulk operation; with $wait, Cloudflare is asked a
	 * few times right away (for deactivation, after which nothing can ask).
	 *
	 * @param string $reason Why, for the state.
	 * @param bool   $wait   Wait briefly for Cloudflare's confirmation.
	 * @return bool Whether the list is confirmed empty now.
	 */
	public function clear_remote( string $reason, bool $wait = false ): bool {
		return (bool) $this->locked( self::lock_wait(), fn(): bool => $this->clear_locked( $reason, $wait ), static fn(): bool => false );
	}

	/**
	 * Body of clear_remote(), under the lock.
	 *
	 * @param string $reason Why, for the state.
	 * @param bool   $wait   Wait briefly for Cloudflare's confirmation.
	 */
	private function clear_locked( string $reason, bool $wait ): bool {
		$state = self::state();
		$dest  = ! empty( $state['dest'] ) ? (array) $state['dest'] : $this->destination();
		if ( '' === $this->token() || '' === (string) ( $dest['account'] ?? '' ) || '' === (string) ( $dest['list'] ?? '' ) || ! $this->manages_items() ) {
			return ! $this->manages_items();
		}
		if ( ! $this->intend( $dest, 'empty' ) ) {
			return false;
		}
		$sent  = $this->send( $dest, array() );
		$state = array_merge(
			self::state(),
			array(
				'time'      => time(),
				'ok'        => $sent['ok'],
				'dest'      => $dest,
				'want'      => 'empty',
				'status'    => $sent['status'],
				'operation' => $sent['operation'],
				'checks'    => 0,
				'items'     => $sent['ok'] ? md5( '' ) : (string) ( $state['items'] ?? '' ),
				'reason'    => $reason,
				/* translators: 1: reason, 2: error. */
				'error'     => $sent['ok'] ? '' : sprintf( __( 'Could not empty the Cloudflare list (%1$s): %2$s. Its rules are still active at Cloudflare; empty the list or delete the WAF rule there.', 'sentinel-shield' ), $reason, $sent['error'] ),
			)
		);
		if ( $sent['ok'] ) {
			$state['count'] = 0;
		}
		if ( ! $this->save( $state ) ) {
			return false;
		}
		if ( $wait ) {
			/**
			 * Seconds between confirmation checks while waiting (deactivation).
			 *
			 * @param int $delay Seconds.
			 */
			$delay = max( 0, (int) apply_filters( 'sentinel_shield_cloudflare_poll_delay', 2 ) );
			for ( $i = 0; $i < 5; $i++ ) {
				if ( 'applying' !== ( self::state()['status'] ?? '' ) ) {
					break;
				}
				if ( $delay ) {
					sleep( $delay );
				}
				$this->check_operation();
			}
			return 'empty' === ( self::state()['status'] ?? '' );
		}
		$this->follow_up( $state );
		return 'empty' === $state['status'];
	}

	/**
	 * After settings are saved: sync switched off empties the list; a new
	 * account or list is synced soon (the old list is emptied first).
	 */
	public function settings_saved(): void {
		$this->settings->refresh();
		if ( ! $this->settings->get( 'cloudflare.sync', false ) ) {
			$this->clear_remote( __( 'sync switched off', 'sentinel-shield' ) );
			return;
		}
		$dest = self::state()['dest'] ?? null;
		if ( $this->enabled() && null !== $dest && $dest !== $this->destination() ) {
			wp_clear_scheduled_hook( self::CRON );
			wp_schedule_single_event( time() + 5, self::CRON );
		}
	}

	/**
	 * Whether the managed list may still hold items: anything except a list
	 * confirmed empty, or one confirmed active with no items.
	 */
	public function manages_items(): bool {
		$state = self::state();
		return match ( (string) ( $state['status'] ?? '' ) ) {
			'', 'empty', 'cleared' => false,
			'active'               => ! empty( $state['count'] ),
			default                => true, // applying, failed, unknown: the remote list may hold items.
		};
	}

	/**
	 * Records, before a request that changes a list, that its content is not
	 * known until Cloudflare answers. A worker that dies after the upload
	 * thus leaves "unknown" (retried, and emptied when sync is switched off)
	 * instead of a state that says the list holds nothing.
	 *
	 * @param array<string, string> $dest account, list.
	 * @param string                $want policy or empty.
	 * @return bool False when the lock was lost (nothing may be sent then).
	 */
	private function intend( array $dest, string $want ): bool {
		$saved = $this->save(
			array_merge(
				self::state(),
				array(
					'dest'      => $dest,
					'want'      => $want,
					'status'    => 'unknown',
					'operation' => '',
					'items'     => '',
					'error'     => __( 'An update of the Cloudflare list was interrupted before Cloudflare answered; it is sent again.', 'sentinel-shield' ),
				)
			)
		);
		$this->fallback();
		return $saved;
	}

	/**
	 * A sync later on, in case this request never finishes its own follow-up.
	 */
	private function fallback(): void {
		if ( ! wp_next_scheduled( self::CRON ) ) {
			wp_schedule_single_event( time() + self::INTERVAL, self::CRON );
		}
	}

	/**
	 * Empties a list the settings no longer point at, and remembers it until
	 * Cloudflare confirms it is empty (or keeps retrying).
	 *
	 * @param array<string, string> $dest  account, list.
	 * @param array<string, mixed>  $prior The state that belonged to it.
	 */
	private function retire( array $dest, array $prior ): void {
		$retired = (array) ( $prior['retired'] ?? array() );
		if ( ! empty( $prior['count'] ) || 'empty' !== ( $prior['status'] ?? '' ) ) {
			// Remembered before the request, so a crash cannot forget the list.
			$noted = $this->save(
				array(
					'retired' => array_merge(
						$retired,
						array(
							array(
								'account'   => (string) ( $dest['account'] ?? '' ),
								'list'      => (string) ( $dest['list'] ?? '' ),
								'status'    => 'unknown',
								'operation' => '',
								'checks'    => 0,
								'time'      => time(),
								'error'     => '',
							),
						)
					),
				)
			);
			$this->fallback();
			if ( ! $noted ) {
				return; // The lock was lost: the new holder empties it.
			}
			$sent      = $this->send( $dest, array() );
			$retired[] = array(
				'account'   => (string) ( $dest['account'] ?? '' ),
				'list'      => (string) ( $dest['list'] ?? '' ),
				'status'    => $sent['status'],
				'operation' => $sent['operation'],
				'checks'    => 0,
				'time'      => time(),
				'error'     => $sent['error'],
			);
		}
		$this->save(
			array(
				'retired' => array_values( array_filter( $retired, static fn( array $r ): bool => 'empty' !== ( $r['status'] ?? '' ) ) ),
			)
		);
	}

	/**
	 * Sends the empty list again to retired lists whose emptying failed or was
	 * never confirmed.
	 */
	private function retry_retired(): void {
		$state   = self::state();
		$changed = false;
		foreach ( (array) ( $state['retired'] ?? array() ) as $i => $old ) {
			if ( in_array( $old['status'] ?? '', array( 'failed', 'unknown' ), true ) && time() >= max( (int) ( $old['time'] ?? 0 ) + self::INTERVAL, (int) ( $old['retry_at'] ?? 0 ) ) ) {
				$sent                   = $this->send( $old, array() );
				$state['retired'][ $i ] = array_merge(
					$old,
					array_intersect_key( $sent, array_flip( array( 'status', 'operation', 'error', 'retry_at' ) ) ),
					array(
						'checks' => 0,
						'time'   => time(),
					)
				);
				$changed                = true;
			}
		}
		if ( $changed ) {
			$state['retired'] = array_values( array_filter( (array) $state['retired'], static fn( array $r ): bool => 'empty' !== ( $r['status'] ?? '' ) ) );
			if ( $this->save( $state ) ) {
				$this->follow_up( $state );
			}
		}
	}

	/**
	 * Replaces a list's items.
	 *
	 * @param array<string, string> $dest  account, list.
	 * @param list<string>          $items Items.
	 * @return array{ok:bool, status:string, operation:string, error:string, retry_at:int}
	 */
	private function send( array $dest, array $items ): array {
		$body   = array_map(
			static fn( string $ip ): array => array(
				'ip'      => $ip,
				'comment' => 'Sentinel Shield',
			),
			$items
		);
		$result = $this->request( 'PUT', '/items', $body, '', $dest );
		if ( is_wp_error( $result ) ) {
			$data = $result->get_error_data();
			return array(
				'ok'        => false,
				'status'    => 'failed',
				'operation' => '',
				'error'     => $result->get_error_message(),
				'retry_at'  => is_array( $data ) && ! empty( $data['retry_after'] ) ? time() + (int) $data['retry_after'] : 0,
			);
		}
		$operation = (string) ( $result['result']['operation_id'] ?? '' );
		return array(
			'retry_at'  => 0,
			'ok'        => true,
			// Without an operation ID Cloudflare applied the change synchronously.
			'status'    => '' !== $operation ? 'applying' : ( $items ? 'active' : 'empty' ),
			'operation' => $operation,
			'error'     => '',
		);
	}

	/**
	 * Asks Cloudflare about one bulk operation.
	 *
	 * @param array<string, mixed> $entry State (or retired entry) with operation and checks.
	 * @param string               $want  policy or empty.
	 * @return array<string, mixed> Changed fields.
	 */
	private function poll( array $entry, string $want ): array {
		$account = (string) ( $entry['dest']['account'] ?? $entry['account'] ?? $this->account() );
		$result  = $this->request( 'GET', '', null, sprintf( self::BULK, rawurlencode( $account ), rawurlencode( (string) $entry['operation'] ) ) );
		$checks  = (int) ( $entry['checks'] ?? 0 ) + 1;
		$status  = is_wp_error( $result ) ? '' : (string) ( $result['result']['status'] ?? '' );
		if ( 'completed' === $status ) {
			return array(
				'checks' => $checks,
				'status' => 'empty' === $want ? 'empty' : 'active',
				'error'  => '',
			);
		}
		if ( 'failed' === $status ) {
			return array(
				'checks' => $checks,
				'status' => 'failed',
				'ok'     => false,
				'error'  => (string) ( $result['result']['error'] ?? __( 'Cloudflare reported that the list update failed.', 'sentinel-shield' ) ),
			);
		}
		if ( $checks >= 20 ) {
			return array(
				'checks' => $checks,
				'status' => 'unknown',
				'error'  => is_wp_error( $result ) ? $result->get_error_message() : __( 'Cloudflare did not confirm the update in time.', 'sentinel-shield' ),
			);
		}
		return array( 'checks' => $checks );
	}

	/**
	 * Schedules what a state needs next: a confirmation check while anything
	 * is applying, a retry after INTERVAL when something failed or was never
	 * confirmed.
	 *
	 * @param array<string, mixed> $state State.
	 */
	private function follow_up( array $state ): void {
		$statuses = array_merge( array( (string) ( $state['status'] ?? '' ) ), array_map( static fn( $r ): string => (string) ( $r['status'] ?? '' ), (array) ( $state['retired'] ?? array() ) ) );
		if ( in_array( 'applying', $statuses, true ) && ! wp_next_scheduled( self::CHECK ) ) {
			wp_schedule_single_event( time() + 15, self::CHECK );
		}
		if ( array_intersect( array( 'failed', 'unknown' ), $statuses ) ) {
			$at   = max( time() + self::INTERVAL, (int) ( $state['retry_at'] ?? 0 ) );
			$next = wp_next_scheduled( self::CRON );
			// Not before Cloudflare's Retry-After (an earlier fallback sync is moved).
			if ( ! $next || ( ! empty( $state['retry_at'] ) && $next < $at ) ) {
				wp_clear_scheduled_hook( self::CRON );
				wp_schedule_single_event( $at, self::CRON );
			}
		}
	}

	/**
	 * Runs $work under the cloudflare_sync lock (re-entrant: nested calls
	 * share it), or returns $busy() when another worker holds it.
	 *
	 * @template T
	 * @param int          $wait Seconds to wait for the lock.
	 * @param callable():T $work Work.
	 * @param callable():T $busy Result when the lock is held elsewhere.
	 * @return T
	 */
	private function locked( int $wait, callable $work, callable $busy ): mixed {
		if ( ! Mutex::acquire( self::LOCK, $wait ) ) {
			return $busy();
		}
		try {
			return $work();
		} finally {
			Mutex::release( self::LOCK );
		}
	}

	/**
	 * Seconds an explicit action waits for another update to finish.
	 */
	private static function lock_wait(): int {
		/**
		 * Seconds Sync now, WP-CLI, token removal and deactivation wait for an
		 * update already running.
		 *
		 * @param int $seconds Seconds.
		 */
		return max( 0, (int) apply_filters( 'sentinel_shield_cloudflare_lock_wait', self::LOCK_WAIT ) );
	}

	/**
	 * Writes the state, only while this worker still holds the lock.
	 *
	 * @param array<string, mixed> $state State.
	 * @return bool False when the lock was lost (nothing written).
	 */
	private function save( array $state ): bool {
		if ( ! Mutex::renew( self::LOCK ) ) {
			return false;
		}
		update_site_option( self::STATE, $state );
		return true;
	}

	/**
	 * The list the settings point at.
	 *
	 * @return array{account:string, list:string}
	 */
	private function destination(): array {
		return array(
			'account' => $this->account(),
			'list'    => $this->list(),
		);
	}

	/**
	 * Converts CIDR labels to what Cloudflare lists accept: IPv4 addresses or
	 * ranges /8 to /32 and IPv6 ranges /4 to /64, at most MAX_ITEMS. Longer
	 * IPv6 prefixes (single addresses) are skipped, or with $ipv6 "expand"
	 * widened to their /64 unless that /64 contains an allowlisted address.
	 *
	 * @param list<string>    $labels CIDR labels.
	 * @param string          $ipv6   skip or expand.
	 * @param IpRangeSet|null $allow  Allowlisted ranges (never widened over).
	 * @return array{items:list<string>, skipped:int, expanded:int}
	 */
	public static function items( array $labels, string $ipv6 = 'skip', ?IpRangeSet $allow = null ): array {
		$out      = array();
		$skipped  = 0;
		$expanded = 0;
		foreach ( $labels as $label ) {
			$cidr = Cidr::parse( $label );
			if ( null === $cidr ) {
				continue;
			}
			if ( 4 === $cidr->version ) {
				if ( $cidr->prefix < 8 ) {
					++$skipped;
					continue;
				}
				$item = 32 === $cidr->prefix ? (string) inet_ntop( $cidr->start ) : $cidr->to_string();
			} elseif ( $cidr->prefix < 4 ) {
				++$skipped;
				continue;
			} elseif ( $cidr->prefix > 64 ) {
				$wide = Cidr::parse( inet_ntop( $cidr->start ) . '/64' );
				if ( 'expand' !== $ipv6 || null === $wide || ( null !== $allow && RangeMath::subtract( IpRangeSet::from_pairs( array( array( $wide->start, $wide->end ) ) ), $allow )->pairs( 6 ) !== array( array( $wide->start, $wide->end ) ) ) ) {
					++$skipped;
					continue;
				}
				$item = $wide->to_string();
				++$expanded;
			} else {
				$item = $cidr->to_string();
			}
			$out[ $item ] = true;
			if ( count( $out ) >= self::MAX_ITEMS ) {
				break;
			}
		}
		return array(
			'items'    => array_keys( $out ),
			'skipped'  => $skipped,
			'expanded' => $expanded,
		);
	}

	/**
	 * Calls the Cloudflare API.
	 *
	 * @param string                     $method HTTP method.
	 * @param string                     $path   Path after the list URL.
	 * @param array<int, mixed>|null     $body   JSON body.
	 * @param string                     $url    Full URL instead of the list URL.
	 * @param array<string, string>|null $dest   account, list (default: the settings).
	 * @return array<string, mixed>|\WP_Error
	 */
	private function request( string $method, string $path, ?array $body = null, string $url = '', ?array $dest = null ): array|\WP_Error {
		$account = (string) ( $dest['account'] ?? $this->account() );
		$list    = (string) ( $dest['list'] ?? $this->list() );
		if ( '' === $account || ( '' === $list && '' === $url ) || '' === $this->token() ) {
			return new \WP_Error( 'sentinel_shield_cf_config', __( 'Enter the account ID, the list ID and an API token first.', 'sentinel-shield' ) );
		}
		$args = array(
			'method'  => $method,
			'timeout' => 20,
			'headers' => array(
				'Authorization' => 'Bearer ' . $this->token(),
				'Content-Type'  => 'application/json',
			),
		);
		if ( null !== $body ) {
			$args['body'] = (string) wp_json_encode( $body );
		}
		$response = wp_remote_request( '' !== $url ? $url : sprintf( self::API, rawurlencode( $account ), rawurlencode( $list ) ) . $path, $args );
		if ( is_wp_error( $response ) ) {
			return $response;
		}
		$code = (int) wp_remote_retrieve_response_code( $response );
		if ( 429 === $code ) {
			// Rate limited: wait as long as Cloudflare asks (within reason), at least INTERVAL.
			$wait = max( self::INTERVAL, min( DAY_IN_SECONDS, (int) wp_remote_retrieve_header( $response, 'retry-after' ) ) );
			/* translators: %d: seconds. */
			return new \WP_Error( 'sentinel_shield_cf_rate', sprintf( __( 'Cloudflare is limiting the rate of requests; trying again in %d seconds.', 'sentinel-shield' ), $wait ), array( 'retry_after' => $wait ) );
		}
		$data = json_decode( (string) wp_remote_retrieve_body( $response ), true );
		if ( ! is_array( $data ) || empty( $data['success'] ) ) {
			$errors  = is_array( $data ) ? (array) ( $data['errors'] ?? array() ) : array();
			$message = $errors ? implode( '; ', array_map( static fn( $e ): string => (string) ( $e['message'] ?? '' ), $errors ) ) : '';
			/* translators: 1: HTTP status, 2: message from Cloudflare. */
			return new \WP_Error( 'sentinel_shield_cf_api', sprintf( __( 'Cloudflare answered %1$d: %2$s', 'sentinel-shield' ), $code, '' === $message ? __( 'unexpected response', 'sentinel-shield' ) : $message ) );
		}
		return $data;
	}

	/**
	 * Account ID setting.
	 */
	private function account(): string {
		return (string) $this->settings->get( 'cloudflare.account_id', '' );
	}

	/**
	 * List ID setting.
	 */
	private function list(): string {
		return (string) $this->settings->get( 'cloudflare.list_id', '' );
	}

	/**
	 * The decrypted token, or ''.
	 */
	private function token(): string {
		$sealed = get_site_option( self::TOKEN );
		return is_string( $sealed ) ? (string) $this->box->open( $sealed ) : '';
	}
}
