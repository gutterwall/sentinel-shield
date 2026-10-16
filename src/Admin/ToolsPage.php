<?php
/**
 * Tools & Testing: test mode switch, simulators, previews and maintenance.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Admin;

use SentinelShield\Container;
use SentinelShield\Settings;

defined( 'ABSPATH' ) || exit;

/**
 * Everything needed to verify the configuration without locking yourself out.
 */
final class ToolsPage {

	/**
	 * Constructor.
	 *
	 * @param Container $c Services.
	 */
	public function __construct( private Container $c ) {}

	/**
	 * Opens a tool form.
	 *
	 * @param string $tool Tool key.
	 */
	private function open( string $tool ): void {
		View::form_open( 'tool' );
		echo '<input type="hidden" name="tool" value="' . esc_attr( $tool ) . '">';
	}

	/**
	 * Renders the page.
	 */
	public function render(): void {
		if ( ! current_user_can( Admin::cap() ) ) {
			wp_die( esc_html__( 'You do not have permission to view this page.', 'sentinel-shield' ) );
		}
		$settings = $this->c->get( Settings::class );
		$ip       = (string) $this->c->get( 'client_ip' );

		echo '<div class="wrap ss-wrap"><h1>' . esc_html__( 'Tools & Testing', 'sentinel-shield' ) . '</h1>';
		echo '<p>' . esc_html__( 'Use these tools to verify the setup safely. Simulators never change anything. Emergency exits if you ever get locked out: define( \'SENTINEL_SHIELD_DISABLE\', true ); in wp-config.php, or run: wp sentinel unblock <ip>', 'sentinel-shield' ) . '</p>';
		echo '<div class="ss-grid">';

		// Test mode.
		echo '<div class="ss-card"><h2>' . esc_html__( 'Test mode', 'sentinel-shield' ) . '</h2><p>';
		echo $settings->global_test_mode() ? View::pill( __( 'On: logging only', 'sentinel-shield' ), 'warn' ) : View::pill( __( 'Off: enforcing', 'sentinel-shield' ), 'ok' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- pill() escapes.
		echo '</p>';
		foreach ( array(
			'on24' => __( 'Test mode for 24 hours', 'sentinel-shield' ),
			'on'   => __( 'Test mode until turned off', 'sentinel-shield' ),
			'off'  => __( 'Turn off test mode (enforce)', 'sentinel-shield' ),
		) as $mode => $label ) {
			$this->open( 'test_mode' );
			echo '<input type="hidden" name="mode" value="' . esc_attr( $mode ) . '">';
			submit_button( $label, 'off' === $mode ? 'primary' : 'secondary', 'submit', false, 'off' === $mode ? array( 'data-sentinel-confirm' => __( 'Enforce blocking now? Make sure the IP Detection tab shows your real IP.', 'sentinel-shield' ) ) : null );
			echo '</form> ';
		}
		echo '<p class="description">' . esc_html__( 'Per-module overrides are on Settings → Modules. Test mode scope is on Settings → General.', 'sentinel-shield' ) . '</p></div>';

		// Decision simulator.
		$sim = View::take_result( 'simulate' );
		echo '<div class="ss-card"><h2>' . esc_html__( 'Decision simulator', 'sentinel-shield' ) . '</h2>';
		echo '<p class="description">' . esc_html__( 'What would happen to a request from this IP right now?', 'sentinel-shield' ) . '</p>';
		$this->open( 'simulate' );
		echo '<p><label>' . esc_html__( 'IP', 'sentinel-shield' ) . '<br><input type="text" name="ip" class="regular-text code" value="' . esc_attr( is_array( $sim ) ? (string) $sim['ip'] : $ip ) . '" required></label></p>';
		echo '<p><label>' . esc_html__( 'Path', 'sentinel-shield' ) . '<br><input type="text" name="uri" class="regular-text code" value="' . esc_attr( is_array( $sim ) ? (string) $sim['uri'] : '/wp-login.php' ) . '"></label></p>';
		echo '<p><label><input type="checkbox" name="ignore_allowlist" value="1"> ' . esc_html__( 'Ignore the allowlist (would this IP be blocked without it?)', 'sentinel-shield' ) . '</label></p>';
		submit_button( __( 'Simulate', 'sentinel-shield' ), 'secondary', 'submit', false );
		echo '</form>';
		if ( is_array( $sim ) ) {
			$state = 'block' === $sim['action'] ? 'bad' : ( 'allow' === $sim['action'] ? 'ok' : 'info' );
			echo '<div class="ss-result"><p>' . View::pill( strtoupper( (string) $sim['action'] ), $state ) . ' '; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- pill() escapes.
			echo esc_html( '' === $sim['reason'] ? __( 'No rule matched.', 'sentinel-shield' ) : (string) $sim['reason'] );
			if ( '' !== $sim['rule'] ) {
				/* translators: 1: rule, 2: source. */
				echo '<br>' . esc_html( sprintf( __( 'Rule: %1$s (source: %2$s)', 'sentinel-shield' ), $sim['rule'], $sim['source'] ) );
			}
			if ( 'block' === $sim['action'] ) {
				echo '<br>' . esc_html( $sim['enforced'] ? __( 'This would be enforced now.', 'sentinel-shield' ) : __( 'Test mode would only log this as "would block".', 'sentinel-shield' ) );
			}
			if ( empty( $sim['enabled'] ) ) {
				echo '<br>' . esc_html__( 'Note: protection or the IP gate module is currently disabled.', 'sentinel-shield' );
			}
			echo '</p></div>';
		}
		echo '</div>';

		// Resolution simulator.
		$res = View::take_result( 'resolve' );
		echo '<div class="ss-card" id="ss-resolve"><h2>' . esc_html__( 'IP resolution simulator', 'sentinel-shield' ) . '</h2>';
		echo '<p class="description">' . esc_html__( 'Test how a trusted proxy preset treats spoofed or chained headers.', 'sentinel-shield' ) . '</p>';
		$this->open( 'resolve' );
		$input = is_array( $res ) ? $res['input'] : array(
			'remote_addr' => '173.245.48.10',
			'headers'     => "CF-Connecting-IP: 198.51.100.23\nX-Forwarded-For: 6.6.6.6, 198.51.100.23",
			'mode'        => $settings->get( 'proxy.mode' ),
		);
		echo '<p><label>REMOTE_ADDR<br><input type="text" name="remote_addr" class="regular-text code" value="' . esc_attr( (string) $input['remote_addr'] ) . '"></label></p>';
		echo '<p><label>' . esc_html__( 'Headers (Name: value, one per line)', 'sentinel-shield' ) . '<br><textarea name="headers" rows="3" class="large-text code">' . esc_textarea( (string) $input['headers'] ) . '</textarea></label></p>';
		echo '<p><label>' . esc_html__( 'Preset', 'sentinel-shield' ) . ' <select name="mode">';
		foreach ( array( 'none', 'cloudflare', 'load_balancer', 'custom' ) as $mode ) {
			echo '<option value="' . esc_attr( $mode ) . '" ' . selected( (string) $input['mode'], $mode, false ) . '>' . esc_html( $mode ) . '</option>';
		}
		echo '</select></label></p>';
		submit_button( __( 'Resolve', 'sentinel-shield' ), 'secondary', 'submit', false );
		echo '</form>';
		if ( is_array( $res ) ) {
			$d = $res['details'];
			echo '<div class="ss-result"><p>' . esc_html__( 'Resolved client IP:', 'sentinel-shield' ) . ' <code>' . esc_html( (string) $d['ip'] ) . '</code><br>';
			/* translators: 1: source, 2: yes/no. */
			echo esc_html( sprintf( __( 'Source: %1$s · REMOTE_ADDR trusted: %2$s', 'sentinel-shield' ), $d['source'], $d['remote_trusted'] ? __( 'yes', 'sentinel-shield' ) : __( 'no', 'sentinel-shield' ) ) );
			echo '</p></div>';
		}
		echo '</div>';

		// Lockout simulator.
		$lock = View::take_result( 'lockout' );
		echo '<div class="ss-card"><h2>' . esc_html__( 'Lockout test', 'sentinel-shield' ) . '</h2>';
		echo '<p class="description">' . esc_html__( 'Runs the real progressive lockout logic for an IP. In test mode it is only logged; otherwise it creates a real block. Use a documentation IP (203.0.113.0/24) or a second device you control. Allowlisted IPs cannot be locked out.', 'sentinel-shield' ) . '</p>';
		$this->open( 'lockout' );
		echo '<p><label>' . esc_html__( 'IP', 'sentinel-shield' ) . '<br><input type="text" name="ip" class="regular-text code" value="203.0.113.10" required></label></p>';
		echo '<p><label>' . esc_html__( 'Module name to record', 'sentinel-shield' ) . '<br><input type="text" name="module" class="regular-text code" value="test"></label></p>';
		submit_button( __( 'Apply lockout', 'sentinel-shield' ), 'secondary', 'submit', false );
		echo '</form>';
		if ( is_array( $lock ) ) {
			echo '<div class="ss-result"><p>';
			if ( ! isset( $lock['step'] ) ) {
				/* translators: %s: IP. */
				echo esc_html( sprintf( __( '%s was not locked out: it is invalid, allowlisted or this server.', 'sentinel-shield' ), (string) $lock['ip'] ) );
			} else {
				$duration = 0 === (int) $lock['duration'] ? __( 'permanent', 'sentinel-shield' ) : human_time_diff( 0, (int) $lock['duration'] );
				/* translators: 1: IP, 2: step, 3: duration. */
				echo esc_html( sprintf( __( '%1$s: step %2$d, %3$s.', 'sentinel-shield' ), $lock['ip'], (int) $lock['step'], $duration ) ) . ' ';
				echo $lock['is_test'] ? View::pill( __( 'test mode: not enforced', 'sentinel-shield' ), 'warn' ) : View::pill( __( 'block created', 'sentinel-shield' ), 'bad' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- pill() escapes.
			}
			echo '</p></div>';
		}
		echo '</div>';

		// Unblock.
		echo '<div class="ss-card"><h2>' . esc_html__( 'Unblock an IP', 'sentinel-shield' ) . '</h2>';
		View::form_open( 'unblock_ip' );
		echo '<p><label>' . esc_html__( 'IP', 'sentinel-shield' ) . '<br><input type="text" name="ip" class="regular-text code" required></label></p>';
		echo '<p><label><input type="checkbox" name="include_ranges" value="1"> ' . esc_html__( 'Also remove range (CIDR) blocks that contain it', 'sentinel-shield' ) . '</label></p>';
		echo '<p><label>' . esc_html__( 'Temporary allow (hours, 0 = none)', 'sentinel-shield' ) . ' <input type="number" name="allow_hours" value="0" min="0" max="720" class="small-text"></label></p>';
		submit_button( __( 'Unblock', 'sentinel-shield' ), 'secondary', 'submit', false );
		echo '</form></div>';

		// Block page & unlock email.
		echo '<div class="ss-card"><h2>' . esc_html__( 'Block page & unlock email', 'sentinel-shield' ) . '</h2>';
		echo '<p><a class="button" target="_blank" rel="noopener" href="' . esc_url( View::action_url( 'preview_block' ) ) . '">' . esc_html__( 'Preview the block page', 'sentinel-shield' ) . '</a></p>';
		echo '<p class="description">' . esc_html__( 'Send yourself a real unlock link to confirm this site can deliver email. If it does not arrive, fix email delivery (e.g. an SMTP plugin) before relying on unlock links.', 'sentinel-shield' ) . '</p>';
		$this->open( 'send_unlock' );
		submit_button( __( 'Email me a test unlock link', 'sentinel-shield' ), 'secondary', 'submit', false );
		echo '</form></div>';

		// Maintenance.
		echo '<div class="ss-card"><h2>' . esc_html__( 'Maintenance', 'sentinel-shield' ) . '</h2>';
		foreach ( array(
			'flush_cache' => __( 'Clear rule cache', 'sentinel-shield' ),
			'maintenance' => __( 'Run housekeeping now', 'sentinel-shield' ),
			'cf_refresh'  => __( 'Refresh Cloudflare ranges', 'sentinel-shield' ),
		) as $tool => $label ) {
			$this->open( $tool );
			submit_button( $label, 'secondary', 'submit', false );
			echo '</form> ';
		}
		echo '</div>';

		// Settings import/export.
		echo '<div class="ss-card"><h2>' . esc_html__( 'Settings import / export', 'sentinel-shield' ) . '</h2>';
		echo '<p><a class="button" href="' . esc_url( View::action_url( 'export_settings' ) ) . '">' . esc_html__( 'Export settings (JSON)', 'sentinel-shield' ) . '</a></p>';
		View::form_open( 'import_settings', true );
		echo '<p><input type="file" name="sentinel_json" accept=".json,application/json"></p>';
		echo '<p><label>' . esc_html__( 'Or paste JSON', 'sentinel-shield' ) . '<br><textarea name="sentinel_json_text" rows="4" class="large-text code"></textarea></label></p>';
		submit_button( __( 'Import settings', 'sentinel-shield' ), 'secondary', 'submit', false, array( 'data-sentinel-confirm' => __( 'Replace all settings with the imported ones?', 'sentinel-shield' ) ) );
		echo '</form></div>';

		echo '</div></div>';
	}
}
