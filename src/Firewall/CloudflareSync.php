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
 */
final class CloudflareSync {

	public const CRON      = 'sentinel_shield_cloudflare_sync';
	public const CHECK     = 'sentinel_shield_cloudflare_check';
	public const TOKEN     = 'sentinel_shield_cf_token';
	public const STATE     = 'sentinel_shield_cf_state';
	public const MAX_ITEMS = 10000;
	public const INTERVAL  = 300;
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
		add_action( self::CRON, array( $this, 'sync' ) );
		add_action( self::CHECK, array( $this, 'check_operation' ) );
		add_action( 'sentinel_shield_settings_saved', array( $this, 'settings_saved' ) );
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
	 * Stores the API token (encrypted), or removes it with ''.
	 *
	 * @param string $token Token.
	 */
	public function set_token( string $token ): void {
		$token = trim( $token );
		if ( '' === $token ) {
			delete_site_option( self::TOKEN );
			return;
		}
		update_site_option( self::TOKEN, $this->box->seal( $token ) );
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
	 * Scheduled syncs skip the upload when Cloudflare already has the same list,
	 * wait while its previous bulk operation is still running, and keep to one
	 * upload per INTERVAL (an emptied policy is sent at once). $force (Sync now,
	 * WP-CLI) always uploads.
	 *
	 * @param bool $force Upload even if unchanged or recent.
	 * @return array<string, mixed> The new state.
	 */
	public function sync( bool $force = false ): array {
		if ( ! $this->enabled() ) {
			return self::state();
		}
		$data  = $this->gate->compile();
		$conv  = self::items( $data['blocked'], (string) $this->settings->get( 'cloudflare.ipv6', 'skip' ), $data['allow_set'] );
		$gen   = (int) ( ( (array) get_site_option( EarlyGate::STATE, array() ) )['generation'] ?? 0 );
		$hash  = md5( implode( ',', $conv['items'] ) );
		$prior = self::state();
		if ( ! $force ) {
			$status = (string) ( $prior['status'] ?? '' );
			if ( ( $prior['items'] ?? '' ) === $hash && in_array( $status, array( 'active', 'applying' ), true ) ) {
				// Same list already there (or on its way): nothing to upload.
				$prior['generation'] = $gen;
				update_site_option( self::STATE, $prior );
				return $prior;
			}
			$wait = 0;
			if ( 'applying' === $status ) {
				$wait = 30;
			} elseif ( $conv['items'] && ! empty( $prior['ok'] ) && time() < (int) ( $prior['time'] ?? 0 ) + self::INTERVAL ) {
				$wait = (int) $prior['time'] + self::INTERVAL - time();
			}
			if ( $wait > 0 ) {
				if ( ! wp_next_scheduled( self::CRON ) ) {
					wp_schedule_single_event( time() + $wait, self::CRON );
				}
				return $prior;
			}
		}
		$items  = array_map(
			static fn( string $ip ): array => array(
				'ip'      => $ip,
				'comment' => 'Sentinel Shield',
			),
			$conv['items']
		);
		$result = $this->request( 'PUT', '/items', $items );
		$state  = array(
			'time'       => time(),
			'ok'         => ! is_wp_error( $result ),
			'count'      => count( $items ),
			'skipped'    => $conv['skipped'],
			'expanded'   => $conv['expanded'],
			'generation' => $gen,
			'status'     => is_wp_error( $result ) ? 'failed' : 'applying',
			'operation'  => is_wp_error( $result ) ? '' : (string) ( $result['result']['operation_id'] ?? '' ),
			'checks'     => 0,
			'items'      => is_wp_error( $result ) ? '' : $hash,
			'error'      => is_wp_error( $result ) ? $result->get_error_message() : '',
		);
		if ( ! is_wp_error( $result ) && '' === $state['operation'] ) {
			$state['status'] = 'active';
		}
		update_site_option( self::STATE, $state );
		if ( 'applying' === $state['status'] ) {
			wp_schedule_single_event( time() + 15, self::CHECK );
		} elseif ( 'failed' === $state['status'] && ! wp_next_scheduled( self::CRON ) ) {
			wp_schedule_single_event( time() + self::INTERVAL, self::CRON );
		}
		return $state;
	}

	/**
	 * Asks Cloudflare whether the last bulk operation finished.
	 *
	 * @return array<string, mixed> The state afterwards.
	 */
	public function check_operation(): array {
		$state = self::state();
		if ( 'applying' !== ( $state['status'] ?? '' ) || '' === (string) ( $state['operation'] ?? '' ) ) {
			return $state;
		}
		$result = $this->request( 'GET', '', null, sprintf( self::BULK, rawurlencode( $this->account() ), rawurlencode( (string) $state['operation'] ) ) );
		++$state['checks'];
		$status = is_wp_error( $result ) ? '' : (string) ( $result['result']['status'] ?? '' );
		if ( 'completed' === $status ) {
			$state['status'] = 'active';
		} elseif ( 'failed' === $status ) {
			$state['status'] = 'failed';
			$state['ok']     = false;
			$state['error']  = (string) ( $result['result']['error'] ?? __( 'Cloudflare reported that the list update failed.', 'sentinel-shield' ) );
		} elseif ( $state['checks'] >= 20 ) {
			$state['status'] = 'unknown';
			$state['error']  = is_wp_error( $result ) ? $result->get_error_message() : __( 'Cloudflare did not confirm the update in time.', 'sentinel-shield' );
		} else {
			wp_schedule_single_event( time() + 15, self::CHECK );
		}
		update_site_option( self::STATE, $state );
		return $state;
	}

	/**
	 * Empties the Cloudflare list (sync switched off, plugin deactivated), so no
	 * block stays active at the edge without Sentinel Shield managing it.
	 *
	 * @param string $reason Why, for the state.
	 * @return bool Whether the list is known to be empty now.
	 */
	public function clear_remote( string $reason ): bool {
		$state = self::state();
		if ( '' === $this->token() || '' === $this->account() || '' === $this->list() || ( empty( $state['count'] ) && 'failed' !== ( $state['status'] ?? '' ) ) ) {
			return true;
		}
		$result = $this->request( 'PUT', '/items', array() );
		update_site_option(
			self::STATE,
			array(
				'time'       => time(),
				'ok'         => ! is_wp_error( $result ),
				'count'      => is_wp_error( $result ) ? (int) ( $state['count'] ?? 0 ) : 0,
				'generation' => (int) ( $state['generation'] ?? 0 ),
				'status'     => is_wp_error( $result ) ? 'failed' : 'cleared',
				'operation'  => is_wp_error( $result ) ? '' : (string) ( $result['result']['operation_id'] ?? '' ),
				'checks'     => 0,
				/* translators: 1: reason, 2: error. */
				'error'      => is_wp_error( $result ) ? sprintf( __( 'Could not empty the Cloudflare list (%1$s): %2$s. Its rules are still active at Cloudflare; empty the list or delete the WAF rule there.', 'sentinel-shield' ), $reason, $result->get_error_message() ) : '',
				'reason'     => $reason,
			)
		);
		return ! is_wp_error( $result );
	}

	/**
	 * After settings are saved: sync switched off empties the list.
	 */
	public function settings_saved(): void {
		$this->settings->refresh();
		if ( ! $this->settings->get( 'cloudflare.sync', false ) ) {
			$this->clear_remote( __( 'sync switched off', 'sentinel-shield' ) );
		}
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
	 * @param string            $method HTTP method.
	 * @param string            $path   Path after the list URL.
	 * @param array<int, mixed> $body  JSON body.
	 * @param string            $url   Full URL instead of the list URL.
	 * @return array<string, mixed>|\WP_Error
	 */
	private function request( string $method, string $path, ?array $body = null, string $url = '' ): array|\WP_Error {
		if ( '' === $this->account() || '' === $this->list() || '' === $this->token() ) {
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
		$response = wp_remote_request( '' !== $url ? $url : sprintf( self::API, rawurlencode( $this->account() ), rawurlencode( $this->list() ) ) . $path, $args );
		if ( is_wp_error( $response ) ) {
			return $response;
		}
		$data = json_decode( (string) wp_remote_retrieve_body( $response ), true );
		if ( ! is_array( $data ) || empty( $data['success'] ) ) {
			$errors  = is_array( $data ) ? (array) ( $data['errors'] ?? array() ) : array();
			$message = $errors ? implode( '; ', array_map( static fn( $e ): string => (string) ( $e['message'] ?? '' ), $errors ) ) : '';
			/* translators: 1: HTTP status, 2: message from Cloudflare. */
			return new \WP_Error( 'sentinel_shield_cf_api', sprintf( __( 'Cloudflare answered %1$d: %2$s', 'sentinel-shield' ), (int) wp_remote_retrieve_response_code( $response ), '' === $message ? __( 'unexpected response', 'sentinel-shield' ) : $message ) );
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
