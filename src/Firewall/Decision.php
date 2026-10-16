<?php
/**
 * Outcome of evaluating a request.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Firewall;

defined( 'ABSPATH' ) || exit;

/**
 * Immutable decision: pass, allow (allowlisted) or block.
 */
final class Decision {

	public const PASS  = 'pass';
	public const ALLOW = 'allow';
	public const BLOCK = 'block';

	/**
	 * Constructor.
	 *
	 * @param string                    $action PASS, ALLOW or BLOCK.
	 * @param string                    $reason Machine or human reason.
	 * @param string                    $module Deciding module.
	 * @param array<string, mixed>|null $rule   Matching rule row, if any.
	 */
	public function __construct(
		public readonly string $action,
		public readonly string $reason = '',
		public readonly string $module = '',
		public readonly ?array $rule = null
	) {}

	/**
	 * Whether this decision blocks.
	 */
	public function is_block(): bool {
		return self::BLOCK === $this->action;
	}
}
