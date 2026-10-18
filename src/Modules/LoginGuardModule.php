<?php
/**
 * Login brute-force protection module.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Modules;

use SentinelShield\Container;
use SentinelShield\Login\BruteForceGuard;

defined( 'ABSPATH' ) || exit;

/**
 * Counts failed logins and applies the per-IP and per-account limits.
 */
final class LoginGuardModule implements ModuleInterface {

	/**
	 * {@inheritDoc}
	 */
	public function slug(): string {
		return 'login_guard';
	}

	/**
	 * {@inheritDoc}
	 *
	 * @param Container $container Services.
	 */
	public function register( Container $container ): void {
		$container->get( BruteForceGuard::class )->register();
	}
}
