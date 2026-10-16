<?php
/**
 * Progressive lockouts, exposed to other modules through an action.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Modules;

use SentinelShield\Container;
use SentinelShield\Http\Request;
use SentinelShield\Lockout\Lockout;
use SentinelShield\Lockout\LockoutService;
use SentinelShield\Repository\EventRepository;

defined( 'ABSPATH' ) || exit;

/**
 * Usage from any module or third-party code:
 *     do_action( 'sentinel_shield_lockout', $ip, 'login', 'Too many failed logins' );
 * Fires `sentinel_shield_locked_out` with the Lockout object afterwards.
 */
final class LockoutModule implements ModuleInterface {

	/**
	 * {@inheritDoc}
	 */
	public function slug(): string {
		return 'lockout';
	}

	/**
	 * {@inheritDoc}
	 *
	 * @param Container $container Services.
	 */
	public function register( Container $container ): void {
		add_action(
			'sentinel_shield_lockout',
			static function ( string $ip, string $module = 'manual', string $reason = '' ) use ( $container ): void {
				self::apply( $container, $ip, $module, $reason );
			},
			10,
			3
		);
	}

	/**
	 * Applies a lockout and logs it.
	 *
	 * @param Container $container Services.
	 * @param string    $ip        IP.
	 * @param string    $module    Module.
	 * @param string    $reason    Reason.
	 */
	public static function apply( Container $container, string $ip, string $module, string $reason ): ?Lockout {
		$lockout = $container->get( LockoutService::class )->lock( $ip, $module, $reason );
		if ( null === $lockout ) {
			return null;
		}
		$container->get( EventRepository::class )->log(
			$lockout->is_test ? 'would_lockout' : 'lockout',
			array(
				'ip'         => $lockout->ip,
				'module'     => $module,
				'reason'     => $reason,
				'uri'        => Request::uri(),
				'user_agent' => Request::user_agent(),
				'is_test'    => $lockout->is_test,
				'context'    => array(
					'step'     => $lockout->step,
					'duration' => $lockout->duration,
					'expires'  => $lockout->expires,
				),
			)
		);
		do_action( 'sentinel_shield_locked_out', $lockout );
		return $lockout;
	}
}
