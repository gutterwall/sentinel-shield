<?php
/**
 * A stand-in for Cloudflare's list API.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Tests\Fakes;

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
