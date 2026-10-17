<?php
/**
 * Tabbed settings page generated from SettingsSchema.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Admin;

use SentinelShield\Container;
use SentinelShield\Feeds\FeedCatalog;
use SentinelShield\Feeds\FeedUpdater;
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

		if ( 'docs' === $tab ) {
			( new DocsTab( $this->c ) )->render();
			echo '</div>';
			return;
		}
		if ( 'ip_detection' === $tab ) {
			$this->ip_panel( $settings );
		} elseif ( 'general' === $tab ) {
			$this->test_mode_panel( $settings );
		} elseif ( 'lockout' === $tab ) {
			$this->lockout_panel( $settings );
		} elseif ( 'blocklists' === $tab ) {
			$this->blocklists_panel( $settings );
		} elseif ( 'geo' === $tab ) {
			( new GeoPanel( $this->c ) )->render();
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
	 * Feed status, update buttons and privacy notes on the Blocklists tab.
	 *
	 * @param Settings $settings Settings.
	 */
	private function blocklists_panel( Settings $settings ): void {
		$updater = $this->c->get( FeedUpdater::class );
		$state   = $updater->state();
		$enabled = $updater->enabled();

		echo '<div class="ss-card"><h2>' . esc_html__( 'Public blocklists', 'sentinel-shield' ) . '</h2>';
		echo '<p>' . esc_html__( 'Tick the lists you want below and save. Enabled lists are downloaded automatically and combined: an IP is blocked if any enabled list contains it, and turning one list off never unblocks an IP that another enabled list or your own rules still block. Your allowlist always wins, and this server\'s own IPs are never blocked by a list.', 'sentinel-shield' ) . '</p>';
		if ( ! $settings->is_module_enabled( 'feeds' ) ) {
			echo '<div class="notice notice-warning inline"><p>' . esc_html__( 'The "Blocklist feeds" module is off on the Modules tab, so lists are neither downloaded nor enforced.', 'sentinel-shield' ) . '</p></div>';
		} elseif ( $enabled && $settings->is_test_mode_chain( 'feeds', 'ip_gate' ) ) {
			echo '<div class="notice notice-info inline"><p>' . esc_html__( 'Blocklists are in test mode: matching visitors are logged as "would block" in the Events log but not blocked.', 'sentinel-shield' ) . '</p></div>';
		}

		echo '<div class="ss-scroll"><table class="widefat striped"><thead><tr>';
		foreach ( array( __( 'List', 'sentinel-shield' ), __( 'Terms', 'sentinel-shield' ), __( 'Ranges', 'sentinel-shield' ), __( 'Last checked', 'sentinel-shield' ), __( 'Last changed', 'sentinel-shield' ), __( 'Next check', 'sentinel-shield' ), '' ) as $heading ) {
			echo '<th>' . esc_html( $heading ) . '</th>';
		}
		echo '</tr></thead><tbody>';
		foreach ( FeedCatalog::all() as $slug => $feed ) {
			$on    = in_array( $slug, $enabled, true );
			$entry = $state[ $slug ] ?? array();
			$terms = (string) $feed['terms'];
			echo '<tr><td><strong>' . esc_html( (string) $feed['name'] ) . '</strong>';
			echo $on ? ' ' . View::pill( __( 'On', 'sentinel-shield' ), 'ok' ) : ''; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- pill() escapes.
			if ( ! empty( $entry['error'] ) ) {
				echo '<br><span class="ss-error">' . esc_html( (string) $entry['error'] ) . '</span>';
			}
			echo '</td><td>' . View::pill( FeedCatalog::terms_label( $terms ), FeedCatalog::TERMS_FREE === $terms ? 'ok' : 'warn' ) . '</td>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- pill() escapes.
			echo '<td>' . esc_html( $on && isset( $entry['count'] ) ? number_format_i18n( (int) $entry['count'] ) : '—' ) . '</td>';
			foreach ( array( 'last_check', 'last_change', 'next_due' ) as $key ) {
				$time = (int) ( $entry[ $key ] ?? 0 );
				if ( ! $on ) {
					$text = '—';
				} elseif ( 'next_due' === $key && $time <= time() ) {
					$text = __( 'Due now', 'sentinel-shield' );
				} else {
					$text = $time > 0 ? wp_date( 'Y-m-d H:i', $time ) : __( 'Never', 'sentinel-shield' );
				}
				echo '<td>' . esc_html( (string) $text ) . '</td>';
			}
			echo '<td>';
			if ( $on ) {
				View::form_open( 'feeds_update' );
				echo '<input type="hidden" name="feed" value="' . esc_attr( $slug ) . '">';
				submit_button( __( 'Update now', 'sentinel-shield' ), 'small', 'submit', false );
				echo '</form>';
			}
			echo '</td></tr>';
		}
		echo '</tbody></table></div>';
		if ( $enabled ) {
			echo '<p>';
			View::form_open( 'feeds_update' );
			echo '<input type="hidden" name="feed" value="all">';
			submit_button( __( 'Update all enabled lists now', 'sentinel-shield' ), 'secondary', 'submit', false );
			echo '</form></p>';
		}

		echo '<h3>' . esc_html__( 'Privacy and fair use', 'sentinel-shield' ) . '</h3><ul class="ul-disc">';
		echo '<li>' . esc_html__( 'Each enabled list is downloaded by this server directly from its provider (some via GitHub). The provider sees your server\'s IP address and when it checks for updates. Nothing about your visitors is sent.', 'sentinel-shield' ) . '</li>';
		echo '<li>' . esc_html__( 'Downloads use a generic "SentinelShield" user agent without your site address, ask the provider whether the list changed first, and are spread out with a random delay.', 'sentinel-shield' ) . '</li>';
		echo '<li>' . esc_html__( 'If a download fails or looks incomplete, the previous copy keeps protecting the site and the next try is delayed (1 h, 2 h, 4 h ...).', 'sentinel-shield' ) . '</li>';
		echo '<li>' . esc_html__( 'Lists marked "Non-commercial only" may not be used on commercial sites; lists marked "Check provider terms" do not state reuse terms clearly. Read the linked terms before enabling them.', 'sentinel-shield' ) . '</li>';
		echo '</ul>';
		echo '<p>' . esc_html__( 'Prefer to manage a list yourself?', 'sentinel-shield' ) . ' <a href="' . esc_url( Admin::url( 'sentinel-shield-rules' ) ) . '">' . esc_html__( 'Upload it on the IP Rules page', 'sentinel-shield' ) . '</a> ' . esc_html__( '(CSV or plain text, one IP or CIDR per line). Uploaded entries become manual rules.', 'sentinel-shield' ) . '</p>';
		echo '</div>';
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
			__( 'Source', 'sentinel-shield' )        => $details['source'],
			__( 'Preset in use', 'sentinel-shield' ) => $details['mode'],
			__( 'REMOTE_ADDR trusted?', 'sentinel-shield' ) => $details['remote_trusted'] ? __( 'yes', 'sentinel-shield' ) : __( 'no', 'sentinel-shield' ),
			__( 'Header read', 'sentinel-shield' )   => '' === $details['header'] ? '—' : $details['header'],
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
