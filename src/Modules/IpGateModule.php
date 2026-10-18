<?php
/**
 * IP allowlist/blocklist enforcement.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Modules;

use SentinelShield\Container;
use SentinelShield\Firewall\Gate;

defined( 'ABSPATH' ) || exit;

/**
 * Enforces immediately while the plugin file loads, the earliest point a regular
 * plugin can run. The optional early firewall (early-gate.php) runs earlier still.
 */
final class IpGateModule implements ModuleInterface {

	/**
	 * {@inheritDoc}
	 */
	public function slug(): string {
		return 'ip_gate';
	}

	/**
	 * {@inheritDoc}
	 *
	 * @param Container $container Services.
	 */
	public function register( Container $container ): void {
		$container->get( Gate::class )->enforce();
	}
}
