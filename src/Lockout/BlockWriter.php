<?php
/**
 * Block creation contract.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Lockout;

defined( 'ABSPATH' ) || exit;

/**
 * Writes the block that a lockout produces.
 */
interface BlockWriter {

	/**
	 * Blocks a single IP.
	 *
	 * @param string   $ip      IP text.
	 * @param int|null $expires Unix expiry, null = permanent.
	 * @param string   $reason  Reason.
	 * @param string   $source  Source, e.g. "lockout_login".
	 */
	public function block( string $ip, ?int $expires, string $reason, string $source ): bool;
}
