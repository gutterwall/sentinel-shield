<?php
/**
 * Tabbed settings page generated from SettingsSchema.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Admin;

use SentinelShield\Container;
use SentinelShield\Http\Request;
use SentinelShield\Net\ClientIpFactory;
use SentinelShield\Net\CloudflareRanges;
use SentinelShield\Safety\SafetyGuard;
use SentinelShield\Settings;
use SentinelShield\SettingsSchema;

defined( 'ABSPATH' ) || exit;

/**
 * One tab per area; every field shows help text and its recommended value.
 */
final class SettingsPage {

	/**
	 * Constructor.
	 *
	 * @param Container $c Services.
	 */
	public function __construct( private Container $c ) {}

	/**
	 * Renders the page.
	 */
	public function render(): void {
		if ( ! current_user_can( Admin::cap() ) ) {
			wp_die( esc_html__( 'You do not have permission to view this page.', 'sentinel-shield' ) );
		}
		$settings = $this->c->get( Settings::class );
		$tabs     = SettingsSchema::tabs();
		$tab      = isset( $_GET['tab'] ) ? sanitize_key( wp_unslash( $_GET['tab'] ) ) : 'general'; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Navigation only.
		$tab      = isset( $tabs[ $tab ] ) ? $tab : 'general';
		$values   = $settings->network_settings();

		echo '<div class="wrap ss-wrap"><h1>' . esc_html__( 'Sentinel Shield Settings', 'sentinel-shield' ) . '</h1>';
		echo '<nav class="nav-tab-wrapper">';
		foreach ( $tabs as $slug => $label ) {
			printf( '<a href="%1$s" class="nav-tab %2$s">%3$s</a>', esc_url( Admin::url( 'sentinel-shield-settings', array( 'tab' => $slug ) ) ), $slug === $tab ? 'nav-tab-active' : '', esc_html( $label ) );
		}
		echo '</nav>';

		if ( 'ip_detection' === $tab ) {
			$this->ip_panel( $settings );
		} elseif ( 'general' === $tab ) {
			$this->test_mode_panel( $settings );
		} elseif ( 'lockout' === $tab ) {
			$this->lockout_panel( $settings );
		}

		View::form_open( 'save_settings' );
		echo '<input type="hidden" name="tab" value="' . esc_attr( $tab ) . '">';
		echo '<table class="form-table" role="presentation">';
		foreach ( SettingsSchema::fields() as $field ) {
			if ( $field['tab'] === $tab ) {
				View::field_row( $field, Settings::get_path( $values, (string) $field['key'] ) );
			}
		}
		echo '</table>';
		submit_button( __( 'Save settings', 'sentinel-shield' ) );
		echo '</form></div>';
	}

	/**
	 * Test mode status on the General tab.
	 *
	 * @param Settings $settings Settings.
	 */
	private function test_mode_panel( Settings $settings ): void {
		echo '<div class="ss-card"><h2>' . esc_html__( 'Current state', 'sentinel-shield' ) . '</h2><p>';
		if ( ! $settings->is_enabled() ) {
			echo View::pill( __( 'Protection off', 'sentinel-shield' ), 'bad' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- pill() escapes.
		} elseif ( $settings->global_test_mode() ) {
			echo View::pill( __( 'Test mode: logging only', 'sentinel-shield' ), 'warn' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- pill() escapes.
			$until = (int) $settings->get( 'general.test_mode_until', 0 );
			if ( $until > 0 ) {
				/* translators: %s: date and time. */
				echo ' ' . esc_html( sprintf( __( 'until %s', 'sentinel-shield' ), wp_date( 'Y-m-d H:i', $until ) ) );
			}
		} else {
			echo View::pill( __( 'Enforcing', 'sentinel-shield' ), 'ok' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- pill() escapes.
		}
		echo '</p><p class="description">' . esc_html__( 'Suggested rollout: keep test mode on, check the IP Detection tab, browse the Events log for "would block" entries for a day, then turn test mode off.', 'sentinel-shield' ) . '</p></div>';
	}

	/**
	 * Explains the lockout ladder with current values.
	 *
	 * @param Settings $settings Settings.
	 */
	private function lockout_panel( Settings $settings ): void {
		$steps = array();
		foreach ( $settings->lockout_durations() as $seconds ) {
			$steps[] = 0 === $seconds ? __( 'permanent', 'sentinel-shield' ) : human_time_diff( 0, $seconds );
		}
		echo '<div class="ss-card"><h2>' . esc_html__( 'Escalation ladder', 'sentinel-shield' ) . '</h2><p>';
		/* translators: 1: list of durations, 2: number of days. */
		echo esc_html( sprintf( __( 'Current ladder: %1$s. Offenses older than %2$d days are forgotten.', 'sentinel-shield' ), implode( ' → ', $steps ), (int) $settings->get( 'lockout.repeat_window_days' ) ) );
		echo '</p><p class="description">' . esc_html__( 'Allowlisted IPs and this server are never locked out. In test mode, lockouts are logged as "would lockout" and counted separately so testing never escalates real lockouts.', 'sentinel-shield' ) . '</p></div>';
	}

	/**
	 * Detected IP, raw headers and warnings.
	 *
	 * @param Settings $settings Settings.
	 */
	private function ip_panel( Settings $settings ): void {
		$details  = $this->c->get( ClientIpFactory::class )->from_globals()->details();
		$warnings = $this->c->get( SafetyGuard::class )->detection_warnings( $details );

		echo '<div class="ss-card"><h2>' . esc_html__( 'What Sentinel Shield sees for your request', 'sentinel-shield' ) . '</h2>';
		echo '<p class="ss-big">' . esc_html__( 'Detected IP:', 'sentinel-shield' ) . ' <code>' . esc_html( '' === $details['ip'] ? '—' : $details['ip'] ) . '</code></p>';
		echo '<p>' . esc_html__( 'Compare this with your real public IP (search "what is my IP" from this device). If they differ, change the Trusted Proxy preset below before turning off test mode.', 'sentinel-shield' ) . '</p>';
		echo '<table class="widefat striped ss-narrow"><tbody>';
		$rows = array(
			__( 'Source', 'sentinel-shield' )             => $details['source'],
			__( 'Preset in use', 'sentinel-shield' )      => $details['mode'],
			__( 'REMOTE_ADDR trusted?', 'sentinel-shield' ) => $details['remote_trusted'] ? __( 'yes', 'sentinel-shield' ) : __( 'no', 'sentinel-shield' ),
			__( 'Header read', 'sentinel-shield' )        => '' === $details['header'] ? '—' : $details['header'],
		);
		foreach ( $rows as $label => $value ) {
			echo '<tr><th>' . esc_html( $label ) . '</th><td><code>' . esc_html( (string) $value ) . '</code></td></tr>';
		}
		echo '</tbody></table>';

		foreach ( $warnings as $warning ) {
			echo '<div class="notice notice-warning inline"><p>' . esc_html( $warning ) . '</p></div>';
		}
		if ( ! $warnings ) {
			echo '<div class="notice notice-success inline"><p>' . esc_html__( 'No configuration problems detected.', 'sentinel-shield' ) . '</p></div>';
		}

		echo '<h3>' . esc_html__( 'Raw request headers', 'sentinel-shield' ) . '</h3><table class="widefat striped ss-narrow"><tbody>';
		foreach ( Request::proxy_headers() as $key => $value ) {
			echo '<tr><th><code>' . esc_html( $key ) . '</code></th><td><code>' . esc_html( '' === $value ? '—' : $value ) . '</code></td></tr>';
		}
		echo '</tbody></table>';

		if ( 'cloudflare' === $settings->get( 'proxy.mode' ) ) {
			$cf      = $this->c->get( CloudflareRanges::class );
			$updated = $cf->last_updated();
			echo '<h3>' . esc_html__( 'Cloudflare ranges', 'sentinel-shield' ) . '</h3><p>';
			echo esc_html(
				$updated
					/* translators: 1: count, 2: date. */
					? sprintf( __( '%1$d ranges, last downloaded %2$s. Refreshed weekly.', 'sentinel-shield' ), count( $cf->all() ), wp_date( 'Y-m-d H:i', $updated ) )
					/* translators: %d: count. */
					: sprintf( __( 'Using the %d ranges bundled with the plugin. They will be downloaded on the next weekly refresh.', 'sentinel-shield' ), count( $cf->all() ) )
			);
			echo '</p>';
			View::form_open( 'tool' );
			echo '<input type="hidden" name="tool" value="cf_refresh"><input type="hidden" name="back" value="ip">';
			submit_button( __( 'Refresh now', 'sentinel-shield' ), 'secondary', 'submit', false );
			echo '</form>';
		}
		echo '<p><a href="' . esc_url( Admin::url( 'sentinel-shield-tools' ) . '#ss-resolve' ) . '">' . esc_html__( 'Try other header combinations in the IP resolution simulator →', 'sentinel-shield' ) . '</a></p>';
		echo '</div>';
	}
}
