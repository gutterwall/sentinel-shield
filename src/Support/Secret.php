<?php
/**
 * Per-install HMAC secret.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Support;

defined( 'ABSPATH' ) || exit;

/**
 * Random secret stored as a site option. Usable before pluggable functions
 * (wp_salt) are loaded, which matters on the early block page.
 */
final class Secret {

	public const OPTION = 'sentinel_shield_secret';

	/**
	 * Returns the secret, creating it on first use.
	 */
	public static function get(): string {
		$secret = get_site_option( self::OPTION );
		if ( ! is_string( $secret ) || strlen( $secret ) < 64 ) {
			$secret = bin2hex( random_bytes( 32 ) );
			update_site_option( self::OPTION, $secret );
		}
		return $secret;
	}
}
