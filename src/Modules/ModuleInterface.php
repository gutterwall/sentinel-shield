<?php
/**
 * Feature module contract.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Modules;

use SentinelShield\Container;

defined( 'ABSPATH' ) || exit;

/**
 * Each feature is a module that can be switched on or off independently.
 */
interface ModuleInterface {

	/**
	 * Settings key, e.g. "ip_gate".
	 */
	public function slug(): string;

	/**
	 * Hooks the module into WordPress. Only called when the module is enabled.
	 *
	 * @param Container $container Services.
	 */
	public function register( Container $container ): void;
}
