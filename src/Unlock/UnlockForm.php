<?php
/**
 * HMAC token for the block-page unlock form.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Unlock;

use SentinelShield\Support\Secret;

defined( 'ABSPATH' ) || exit;

/**
 * WordPress nonces need pluggable functions and a session, which a blocked
 * logged-out visitor does not have. This IP-bound, hour-bucketed HMAC gives the
 * same CSRF/replay protection for the unlock form.
 */
final class UnlockForm {

	/**
	 * Token for an IP in the given hour bucket.
	 *
	 * @param string   $ip     Client IP.
	 * @param int|null $bucket Hour bucket, defaults to now.
	 */
	public static function token( string $ip, ?int $bucket = null ): string {
		$bucket = $bucket ?? intdiv( time(), HOUR_IN_SECONDS );
		return hash_hmac( 'sha256', 'unlock|' . $ip . '|' . $bucket, Secret::get() );
	}

	/**
	 * Accepts tokens from the current or previous hour.
	 *
	 * @param string $token Submitted token.
	 * @param string $ip    Client IP.
	 */
	public static function verify( string $token, string $ip ): bool {
		$now = intdiv( time(), HOUR_IN_SECONDS );
		return hash_equals( self::token( $ip, $now ), $token ) || hash_equals( self::token( $ip, $now - 1 ), $token );
	}
}
