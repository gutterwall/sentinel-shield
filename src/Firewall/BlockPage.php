<?php
/**
 * The page shown to blocked visitors.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Firewall;

use SentinelShield\Settings;
use SentinelShield\Support\I18n;
use SentinelShield\Unlock\UnlockForm;

defined( 'ABSPATH' ) || exit;

/**
 * Self-contained HTML (no theme, no external assets) so it renders before WordPress finishes loading.
 */
final class BlockPage {

	/**
	 * Sends the block response and stops execution.
	 *
	 * @param Decision $decision Decision.
	 * @param Settings $settings Settings.
	 * @param string   $ip       Client IP.
	 * @param string   $notice   Optional notice (unlock flow feedback).
	 */
	public static function send( Decision $decision, Settings $settings, string $ip, string $notice = '' ): never {
		I18n::load();
		$is_404 = '404' === $settings->get( 'general.block_response' );
		if ( ! headers_sent() ) {
			status_header( $is_404 ? 404 : 403 );
			nocache_headers();
			header( 'Content-Type: text/html; charset=utf-8' );
			header( 'X-Robots-Tag: noindex, nofollow' );
			header( 'X-Content-Type-Options: nosniff' );
		}
		echo self::html( $decision, $settings, $ip, $notice ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- html() escapes every dynamic value.
		exit;
	}

	/**
	 * Renders the page.
	 *
	 * @param Decision $decision Decision.
	 * @param Settings $settings Settings.
	 * @param string   $ip       Client IP.
	 * @param string   $notice   Optional notice.
	 * @param bool     $preview  Admin preview banner.
	 */
	public static function html( Decision $decision, Settings $settings, string $ip, string $notice = '', bool $preview = false ): string {
		$banner = $preview ? '<p class="preview">' . esc_html__( 'Preview: this is what blocked visitors see. You are not blocked.', 'sentinel-shield' ) . '</p>' : '';

		if ( '404' === $settings->get( 'general.block_response' ) ) {
			return self::wrap( esc_html__( 'Not Found', 'sentinel-shield' ), $banner . '<h1>' . esc_html__( 'Not Found', 'sentinel-shield' ) . '</h1><p>' . esc_html__( 'The requested page could not be found.', 'sentinel-shield' ) . '</p>' );
		}

		$message = trim( (string) $settings->get( 'general.block_message', '' ) );
		if ( '' === $message ) {
			$message = __( 'Your access to this site has been restricted by its security settings. If you believe this is a mistake, contact the site owner and include the details below.', 'sentinel-shield' );
		}
		$body  = $banner;
		$body .= '<h1>' . esc_html__( 'Access denied', 'sentinel-shield' ) . '</h1>';
		$body .= '<p>' . nl2br( esc_html( $message ) ) . '</p>';
		$body .= '<dl>';
		$body .= '<dt>' . esc_html__( 'Your IP address', 'sentinel-shield' ) . '</dt><dd><code>' . esc_html( $ip ) . '</code></dd>';
		if ( '' !== $decision->reason ) {
			$body .= '<dt>' . esc_html__( 'Reason', 'sentinel-shield' ) . '</dt><dd>' . esc_html( $decision->reason ) . '</dd>';
		}
		$body .= '<dt>' . esc_html__( 'Time (UTC)', 'sentinel-shield' ) . '</dt><dd>' . esc_html( gmdate( 'Y-m-d H:i:s' ) ) . '</dd>';
		$body .= '</dl>';

		if ( '' !== $notice ) {
			$body .= '<p class="notice" role="status">' . esc_html( $notice ) . '</p>';
		}

		if ( $settings->is_module_enabled( 'unlock' ) ) {
			$body .= '<form method="post" action="' . esc_url( home_url( '/' ) ) . '">';
			$body .= '<h2>' . esc_html__( 'Are you a site administrator?', 'sentinel-shield' ) . '</h2>';
			$body .= '<p>' . esc_html__( 'Enter the email address of your administrator account and we will send a one-time unlock link.', 'sentinel-shield' ) . '</p>';
			$body .= '<label for="sentinel_email">' . esc_html__( 'Email address', 'sentinel-shield' ) . '</label>';
			$body .= '<input type="email" id="sentinel_email" name="sentinel_email" required autocomplete="email">';
			$body .= '<div class="hp" aria-hidden="true"><label for="sentinel_website">Website</label><input type="text" id="sentinel_website" name="sentinel_website" tabindex="-1" autocomplete="off"></div>';
			$body .= '<input type="hidden" name="sentinel_unlock_request" value="1">';
			$body .= '<input type="hidden" name="sentinel_token" value="' . esc_attr( UnlockForm::token( $ip ) ) . '">';
			$body .= '<button type="submit"' . ( $preview ? ' disabled' : '' ) . '>' . esc_html__( 'Send unlock link', 'sentinel-shield' ) . '</button>';
			$body .= '</form>';
		}
		return self::wrap( esc_html__( 'Access denied', 'sentinel-shield' ), $body );
	}

	/**
	 * Wraps body HTML in a minimal document.
	 *
	 * @param string $title Escaped title.
	 * @param string $body  Escaped body.
	 */
	private static function wrap( string $title, string $body ): string {
		$css = 'body{font:16px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#f6f7f7;color:#1d2327;margin:0;padding:2rem 1rem}'
			. 'main{max-width:36rem;margin:0 auto;background:#fff;border:1px solid #dcdcde;border-radius:8px;padding:2rem}'
			. 'h1{margin-top:0;font-size:1.6rem}h2{font-size:1.1rem;margin-top:2rem}dt{font-weight:600}dd{margin:0 0 .5rem}'
			. 'input[type=email]{width:100%;padding:.5rem;box-sizing:border-box;margin:.25rem 0 1rem}'
			. 'button{background:#2271b1;color:#fff;border:0;border-radius:4px;padding:.6rem 1.2rem;cursor:pointer}'
			. '.hp{position:absolute;left:-9999px}.notice{background:#f0f6fc;border-left:4px solid #2271b1;padding:.75rem}'
			. '.preview{background:#fcf9e8;border-left:4px solid #dba617;padding:.75rem}'
			. '@media (prefers-color-scheme:dark){body{background:#1d2327;color:#f0f0f1}main{background:#2c3338;border-color:#3c434a}.notice,.preview{color:#1d2327}}';
		return '<!DOCTYPE html><html lang="' . esc_attr( str_replace( '_', '-', (string) get_locale() ) ) . '"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>' . $title . '</title><style>' . $css . '</style></head><body><main>' . $body . '</main></body></html>';
	}
}
