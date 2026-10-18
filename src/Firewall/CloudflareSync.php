<?php
/**
 * Keeps a Cloudflare IP list in step with the blocklist.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Firewall;

use SentinelShield\Net\Cidr;
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
	public const TOKEN     = 'sentinel_shield_cf_token';
	public const STATE     = 'sentinel_shield_cf_state';
	public const MAX_ITEMS = 10000;
	private const API      = 'https://api.cloudflare.com/client/v4/accounts/%s/rules/lists/%s';

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
	}

	/**
	 * Whether syncing is switched on and configured.
	 */
	public function enabled(): bool {
		return (bool) $this->settings->get( 'cloudflare.sync', false ) && '' !== $this->account() && '' !== $this->list() && '' !== $this->token();
	}

	/**
	 * Schedules a sync half a minute from now (changes in a burst are synced once).
	 */
	public function schedule(): void {
		if ( $this->enabled() && ! wp_next_scheduled( self::CRON ) ) {
			wp_schedule_single_event( time() + 30, self::CRON );
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
	 * Replaces the list's items with the current enforced block rules.
	 *
	 * @param list<string>|null $labels Rule labels (default: compiled now).
	 * @return array<string, mixed> The new state.
	 */
	public function sync( $labels = null ): array {
		if ( ! $this->enabled() ) {
			return self::state();
		}
		$labels = is_array( $labels ) ? $labels : $this->gate->compile()['blocked'];
		$items  = array();
		foreach ( self::items( $labels ) as $ip ) {
			$items[] = array(
				'ip'      => $ip,
				'comment' => 'Sentinel Shield',
			);
		}
		$response = $this->request( 'PUT', '/items', $items );
		$state    = array(
			'time'  => time(),
			'ok'    => ! is_wp_error( $response ),
			'count' => count( $items ),
			'error' => is_wp_error( $response ) ? $response->get_error_message() : '',
		);
		update_site_option( self::STATE, $state );
		return $state;
	}

	/**
	 * Converts rule labels to what Cloudflare lists accept: IPv4 addresses or
	 * ranges /8 to /32, IPv6 ranges /4 to /64 (single IPv6 addresses become
	 * their /64), at most MAX_ITEMS.
	 *
	 * @param list<string> $labels CIDR labels.
	 * @return list<string>
	 */
	public static function items( array $labels ): array {
		$out = array();
		foreach ( $labels as $label ) {
			$cidr = Cidr::parse( $label );
			if ( null === $cidr ) {
				continue;
			}
			if ( 4 === $cidr->version ) {
				if ( $cidr->prefix < 8 ) {
					continue;
				}
				$item = 32 === $cidr->prefix ? (string) inet_ntop( $cidr->start ) : $cidr->to_string();
			} else {
				if ( $cidr->prefix < 4 ) {
					continue;
				}
				$item = $cidr->prefix > 64 ? (string) Cidr::parse( inet_ntop( $cidr->start ) . '/64' )?->to_string() : $cidr->to_string();
			}
			$out[ $item ] = true;
			if ( count( $out ) >= self::MAX_ITEMS ) {
				break;
			}
		}
		return array_keys( $out );
	}

	/**
	 * Calls the Cloudflare API.
	 *
	 * @param string            $method HTTP method.
	 * @param string            $path   Path after the list URL.
	 * @param array<int, mixed> $body  JSON body.
	 * @return array<string, mixed>|\WP_Error
	 */
	private function request( string $method, string $path, ?array $body = null ): array|\WP_Error {
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
		$response = wp_remote_request( sprintf( self::API, rawurlencode( $this->account() ), rawurlencode( $this->list() ) ) . $path, $args );
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
