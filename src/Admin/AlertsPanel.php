<?php
/**
 * Settings → Alerts & Audit Log: delivery status and setup.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Admin;

use SentinelShield\Audit\AuditExporter;
use SentinelShield\Container;
use SentinelShield\Settings;
use SentinelShield\Support\Mailer;

defined( 'ABSPATH' ) || exit;

/**
 * Shows whether alerts actually reach someone.
 */
final class AlertsPanel {

	/**
	 * Constructor.
	 *
	 * @param Container $c Services.
	 */
	public function __construct( private Container $c ) {}

	/**
	 * Renders the panel.
	 */
	public function render(): void {
		$settings = $this->c->get( Settings::class );
		$export   = $this->c->get( AuditExporter::class );

		echo '<div class="ss-card" id="ss-delivery"><h2>' . esc_html__( 'Alert delivery', 'sentinel-shield' ) . '</h2>';
		/* translators: %s: email address. */
		echo '<p>' . esc_html( sprintf( __( 'Alert emails go to the site admin address, %s (Settings → General).', 'sentinel-shield' ), (string) get_site_option( 'admin_email' ) ) ) . '</p>';
		$kinds  = array(
			'alert'  => __( 'Security alerts', 'sentinel-shield' ),
			'code'   => __( 'Two-factor codes', 'sentinel-shield' ),
			'unlock' => __( 'Unlock links', 'sentinel-shield' ),
			'test'   => __( 'Test alerts', 'sentinel-shield' ),
		);
		$health = Mailer::health();
		echo '<table class="widefat striped ss-narrow"><thead><tr><th>' . esc_html__( 'Email', 'sentinel-shield' ) . '</th><th>' . esc_html__( 'Last accepted by the mail system', 'sentinel-shield' ) . '</th><th>' . esc_html__( 'Last refused', 'sentinel-shield' ) . '</th></tr></thead><tbody>';
		foreach ( $kinds as $kind => $label ) {
			$entry = (array) ( $health[ $kind ] ?? array() );
			$fail  = empty( $entry['last_fail'] ) ? '—' : wp_date( 'Y-m-d H:i', (int) $entry['last_fail'] ) . ': ' . (string) ( $entry['error'] ?? '' );
			echo '<tr><td>' . esc_html( $label ) . ( Mailer::failing( $kind ) ? ' ' . View::pill( __( 'Failing', 'sentinel-shield' ), 'bad' ) : '' ) . '</td><td>' . esc_html( empty( $entry['last_ok'] ) ? '—' : wp_date( 'Y-m-d H:i', (int) $entry['last_ok'] ) ) . '</td><td>' . esc_html( $fail ) . '</td></tr>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- pill() escapes.
		}
		echo '</tbody></table>';
		echo '<p class="description">' . esc_html__( 'WordPress only knows whether the mail server accepted a message, not whether it arrived. Send a test and check your inbox (and spam folder); an SMTP plugin makes delivery much more reliable than PHP\'s mail().', 'sentinel-shield' ) . '</p>';
		View::form_open( 'alerts' );
		echo '<input type="hidden" name="op" value="test">';
		submit_button( __( 'Send a test alert through every channel', 'sentinel-shield' ), 'secondary', 'submit', false );
		echo '</form></div>';

		echo '<div class="ss-card" id="ss-audit"><h2>' . esc_html__( 'Remote audit log', 'sentinel-shield' ) . '</h2>';
		$state = AuditExporter::state();
		if ( '' === $export->webhook() ) {
			echo '<p>' . esc_html__( 'No webhook set: events stay in this site\'s database only.', 'sentinel-shield' ) . '</p>';
		} else {
			$backlog = $export->backlog();
			$lines   = array();
			/* translators: %s: number of events. */
			$lines[] = sprintf( __( '%s events sent so far.', 'sentinel-shield' ), number_format_i18n( (int) ( $state['sent'] ?? 0 ) ) );
			if ( ! empty( $state['last_ok'] ) ) {
				/* translators: %s: date. */
				$lines[] = sprintf( __( 'Last delivery %s.', 'sentinel-shield' ), wp_date( 'Y-m-d H:i:s', (int) $state['last_ok'] ) );
			}
			/* translators: %d: number of events. */
			$lines[] = sprintf( _n( '%d event waiting.', '%d events waiting.', $backlog, 'sentinel-shield' ), $backlog );
			echo '<p>' . esc_html( implode( ' ', $lines ) ) . '</p>';
			if ( ! empty( $state['failures'] ) ) {
				/* translators: 1: number of failures, 2: error, 3: date. */
				echo '<p>' . View::pill( __( 'Failing', 'sentinel-shield' ), 'bad' ) . ' ' . esc_html( sprintf( __( '%1$d failed attempts. Last error: %2$s. Next try %3$s.', 'sentinel-shield' ), (int) $state['failures'], (string) $state['error'], wp_date( 'H:i', (int) $state['next_try'] ) ) ) . '</p>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- pill() escapes.
			}
			if ( $backlog > 0 ) {
				View::form_open( 'alerts' );
				echo '<input type="hidden" name="op" value="send">';
				submit_button( __( 'Send waiting events now', 'sentinel-shield' ), 'secondary', 'submit', false );
				echo '</form>';
			}
		}
		$beat = (array) ( $state['heartbeat'] ?? array() );
		if ( '' !== (string) $settings->get( 'audit.heartbeat_url', '' ) ) {
			echo '<p>' . esc_html__( 'Heartbeat:', 'sentinel-shield' ) . ' ' . ( empty( $beat ) ? esc_html__( 'not sent yet (hourly).', 'sentinel-shield' ) : ( ! empty( $beat['ok'] ) ? View::pill( __( 'OK', 'sentinel-shield' ), 'ok' ) . ' ' . esc_html( wp_date( 'Y-m-d H:i', (int) $beat['time'] ) ) : View::pill( __( 'Failing', 'sentinel-shield' ), 'bad' ) . ' ' . esc_html( (string) $beat['error'] ) ) ) . '</p>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- pill() escapes.
		}

		echo '<h3>' . esc_html__( 'Verifying deliveries', 'sentinel-shield' ) . '</h3>';
		echo '<p>' . esc_html__( 'Each request has the header X-Sentinel-Shield-Signature: t=<unix time>,v1=<hex>. Compute HMAC-SHA256 of "<unix time>.<raw body>" with this secret and compare; reject old timestamps. Each event has seq, prev and hash: hash = SHA-256 of prev, a newline, and the event\'s JSON without seq, prev and hash. A gap in seq or a prev that does not match the previous hash means events are missing.', 'sentinel-shield' ) . '</p>';
		echo '<p><label>' . esc_html__( 'Signing secret', 'sentinel-shield' ) . '<br><input type="text" class="large-text code" readonly value="' . esc_attr( AuditExporter::secret() ) . '" onclick="this.select()"></label></p>';
		View::form_open( 'alerts' );
		echo '<input type="hidden" name="op" value="new_secret">';
		submit_button( __( 'Create a new secret', 'sentinel-shield' ), 'small', 'submit', false, array( 'onclick' => 'return confirm(' . wp_json_encode( __( 'The receiver must be updated with the new secret, or it will reject deliveries. Continue?', 'sentinel-shield' ) ) . ')' ) );
		echo '</form><p class="description">' . esc_html__( 'Example check in PHP: hash_equals( hash_hmac( "sha256", $t . "." . $body, $secret ), $v1 )', 'sentinel-shield' ) . '</p></div>';
	}
}
