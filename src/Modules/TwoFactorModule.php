<?php
/**
 * Two-factor authentication module.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Modules;

use SentinelShield\Admin\TwoFactorPage;
use SentinelShield\Container;
use SentinelShield\TwoFactor\TwoFactorLogin;

defined( 'ABSPATH' ) || exit;

/**
 * The second login step, plus each user's setup page and profile section.
 */
final class TwoFactorModule implements ModuleInterface {

	/**
	 * {@inheritDoc}
	 */
	public function slug(): string {
		return 'two_factor';
	}

	/**
	 * {@inheritDoc}
	 *
	 * @param Container $container Services.
	 */
	public function register( Container $container ): void {
		$container->get( TwoFactorLogin::class )->register();
		if ( is_admin() ) {
			( new TwoFactorPage( $container ) )->register();
		}
	}
}
