<?php
/**
 * Emailed unlock links.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Modules;

use SentinelShield\Container;
use SentinelShield\Unlock\UnlockService;

defined( 'ABSPATH' ) || exit;

/**
 * Registers the unlock link / form handler.
 */
final class UnlockModule implements ModuleInterface {

	/**
	 * {@inheritDoc}
	 */
	public function slug(): string {
		return 'unlock';
	}

	/**
	 * {@inheritDoc}
	 *
	 * @param Container $container Services.
	 */
	public function register( Container $container ): void {
		$container->get( UnlockService::class )->register();
	}
}
