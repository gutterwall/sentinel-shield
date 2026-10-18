<?php
/**
 * Sends Sentinel Shield's emails and remembers whether they went out.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Support;

defined( 'ABSPATH' ) || exit;

/**
 * An alert that silently fails to send is worse than none: the site owner
 * believes they would be told. Every email goes through here, and the last
 * success and failure per kind (alert, code, unlock, test) are kept for the
 * health card, including the mailer's error message.
 */
final class Mailer {

	public const HEALTH = 'sentinel_shield_mail_health';

	/**
	 * Last wp_mail_failed error during send().
	 *
	 * @var string
	 */
	private static string $error = '';

	/**
	 * Sends an email.
	 *
	 * @param string $to      Recipient.
	 * @param string $subject Subject.
	 * @param string $body    Plain-text body.
	 * @param string $kind    alert, code, unlock or test.
	 */
	public static function send( string $to, string $subject, string $body, string $kind ): bool {
		self::$error = '';
		$catch       = static function ( $error ): void {
			if ( $error instanceof \WP_Error ) {
				self::$error = $error->get_error_message();
			}
		};
		add_action( 'wp_mail_failed', $catch );
		try {
			$ok = (bool) wp_mail( $to, $subject, $body );
		} finally {
			remove_action( 'wp_mail_failed', $catch );
		}
		$health      = self::health();
		$entry       = (array) ( $health[ $kind ] ?? array() );
		$entry['ok'] = $ok;
		if ( $ok ) {
			$entry['last_ok'] = time();
		} else {
			$entry['last_fail'] = time();
			$entry['error']     = '' === self::$error ? __( 'wp_mail() returned false without an error message.', 'sentinel-shield' ) : mb_substr( self::$error, 0, 300 );
		}
		$health[ $kind ] = $entry;
		update_site_option( self::HEALTH, $health );
		return $ok;
	}

	/**
	 * Delivery record per kind: last_ok, last_fail, error.
	 *
	 * @return array<string, array<string, mixed>>
	 */
	public static function health(): array {
		$health = get_site_option( self::HEALTH );
		return is_array( $health ) ? $health : array();
	}

	/**
	 * Whether the most recent attempt of a kind failed.
	 *
	 * @param string $kind Kind.
	 */
	public static function failing( string $kind ): bool {
		$entry = (array) ( self::health()[ $kind ] ?? array() );
		return isset( $entry['ok'] ) && false === $entry['ok'];
	}
}
