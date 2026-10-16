<?php
/**
 * Overview dashboard.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Admin;

use SentinelShield\Container;
use SentinelShield\Net\IpAddress;
use SentinelShield\Repository\BlockRepository;
use SentinelShield\Repository\EventRepository;
use SentinelShield\Safety\SafetyGuard;
use SentinelShield\Settings;

defined( 'ABSPATH' ) || exit;

/**
 * Protection state, your connection, 24-hour counters, top IPs and recent events.
 */
final class DashboardPage {

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
		$rules    = $this->c->get( BlockRepository::class );
		$events   = $this->c->get( EventRepository::class );
		$ip       = (string) $this->c->get( 'client_ip' );
		$since    = time() - DAY_IN_SECONDS;

		echo '<div class="wrap ss-wrap"><h1>' . esc_html__( 'Sentinel Shield', 'sentinel-shield' ) . '</h1><div class="ss-grid ss-grid-4">';

		if ( SafetyGuard::emergency_disabled() ) {
			$state = View::pill( __( 'Disabled by wp-config.php', 'sentinel-shield' ), 'bad' );
		} elseif ( ! $settings->is_enabled() ) {
			$state = View::pill( __( 'Off', 'sentinel-shield' ), 'bad' );
		} elseif ( $settings->global_test_mode() ) {
			$state = View::pill( __( 'Test mode', 'sentinel-shield' ), 'warn' );
		} else {
			$state = View::pill( __( 'Enforcing', 'sentinel-shield' ), 'ok' );
		}
		$allowed = $rules->find_containing( 'allow', (string) IpAddress::to_binary( $ip ) );

		$this->stat( __( 'Protection', 'sentinel-shield' ), $state, '<a href="' . esc_url( Admin::url( 'sentinel-shield-tools' ) ) . '">' . esc_html__( 'Test mode controls', 'sentinel-shield' ) . '</a>' );
		$this->stat( __( 'Your IP', 'sentinel-shield' ), '<code>' . esc_html( $ip ) . '</code>', $allowed ? View::pill( __( 'allowlisted', 'sentinel-shield' ), 'ok' ) : View::pill( __( 'not allowlisted', 'sentinel-shield' ), 'warn' ) );
		$this->stat( __( 'Active rules', 'sentinel-shield' ), esc_html( number_format_i18n( $rules->count_active( 'block' ) ) ) . ' / ' . esc_html( number_format_i18n( $rules->count_active( 'allow' ) ) ), esc_html__( 'blocked / allowed', 'sentinel-shield' ) );
		$this->stat(
			__( 'Last 24 hours', 'sentinel-shield' ),
			esc_html( number_format_i18n( $events->count_since( array( 'blocked' ), $since ) ) ) . ' ' . esc_html__( 'blocked', 'sentinel-shield' ),
			/* translators: 1: would-block count, 2: lockout count. */
			esc_html( sprintf( __( '%1$d would-block · %2$d lockouts', 'sentinel-shield' ), $events->count_since( array( 'would_block', 'would_lockout' ), $since ), $events->count_since( array( 'lockout' ), $since ) ) )
		);
		echo '</div><div class="ss-grid">';

		echo '<div class="ss-card"><h2>' . esc_html__( 'Top IPs (24 h)', 'sentinel-shield' ) . '</h2>';
		$top = $events->top_ips( array( 'blocked', 'would_block', 'lockout', 'would_lockout' ), $since );
		if ( ! $top ) {
			echo '<p>' . esc_html__( 'Nothing to report.', 'sentinel-shield' ) . '</p>';
		} else {
			echo '<table class="widefat striped"><tbody>';
			foreach ( $top as $row ) {
				echo '<tr><td><a href="' . esc_url( Admin::url( 'sentinel-shield-events', array( 'ip' => $row['ip_text'] ) ) ) . '"><code>' . esc_html( (string) $row['ip_text'] ) . '</code></a></td><td>' . esc_html( number_format_i18n( (int) $row['hits'] ) ) . '</td><td>';
				if ( $row['ip_text'] !== $ip ) {
					View::form_open( 'add_rule' );
					echo '<input type="hidden" name="value" value="' . esc_attr( (string) $row['ip_text'] ) . '"><input type="hidden" name="list_type" value="block"><input type="hidden" name="reason" value="' . esc_attr__( 'Blocked from dashboard', 'sentinel-shield' ) . '">';
					submit_button( __( 'Block', 'sentinel-shield' ), 'small', 'submit', false );
					echo '</form>';
				}
				echo '</td></tr>';
			}
			echo '</tbody></table>';
		}
		echo '</div>';

		echo '<div class="ss-card"><h2>' . esc_html__( 'Modules', 'sentinel-shield' ) . '</h2><table class="widefat striped"><tbody>';
		$labels = array(
			'ip_gate' => __( 'IP blocklist & allowlist', 'sentinel-shield' ),
			'lockout' => __( 'Progressive lockouts', 'sentinel-shield' ),
			'unlock'  => __( 'Emailed unlock links', 'sentinel-shield' ),
		);
		foreach ( $labels as $slug => $label ) {
			$on   = $settings->is_module_enabled( $slug );
			$test = $on && 'unlock' !== $slug && $settings->is_test_mode( $slug );
			echo '<tr><td>' . esc_html( $label ) . '</td><td>' . ( $on ? View::pill( $test ? __( 'test mode', 'sentinel-shield' ) : __( 'on', 'sentinel-shield' ), $test ? 'warn' : 'ok' ) : View::pill( __( 'off', 'sentinel-shield' ), 'bad' ) ) . '</td></tr>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- pill() escapes.
		}
		echo '</tbody></table><p><a href="' . esc_url( Admin::url( 'sentinel-shield-settings', array( 'tab' => 'modules' ) ) ) . '">' . esc_html__( 'Configure modules', 'sentinel-shield' ) . '</a></p></div>';
		echo '</div>';

		echo '<div class="ss-card"><h2>' . esc_html__( 'Recent events', 'sentinel-shield' ) . '</h2>';
		[ $recent ] = $events->query( array( 'per_page' => 10 ) );
		$types      = EventsPage::types();
		if ( ! $recent ) {
			echo '<p>' . esc_html__( 'No events yet.', 'sentinel-shield' ) . '</p>';
		} else {
			echo '<table class="widefat striped"><tbody>';
			foreach ( $recent as $row ) {
				echo '<tr><td>' . esc_html( View::time( (string) $row['created_at'] ) ) . '</td><td>' . esc_html( $types[ $row['event'] ] ?? (string) $row['event'] ) . '</td><td><code>' . esc_html( (string) $row['ip_text'] ) . '</code></td><td>' . esc_html( (string) $row['reason'] ) . '</td></tr>';
			}
			echo '</tbody></table>';
		}
		echo '<p><a href="' . esc_url( Admin::url( 'sentinel-shield-events' ) ) . '">' . esc_html__( 'All events →', 'sentinel-shield' ) . '</a></p></div></div>';
	}

	/**
	 * One stat card. $value and $sub must already be escaped HTML.
	 *
	 * @param string $label Label.
	 * @param string $value Escaped HTML.
	 * @param string $sub   Escaped HTML.
	 */
	private function stat( string $label, string $value, string $sub ): void {
		echo '<div class="ss-card ss-stat"><div class="ss-stat-label">' . esc_html( $label ) . '</div><div class="ss-stat-value">' . wp_kses_post( $value ) . '</div><div class="ss-stat-sub">' . wp_kses_post( $sub ) . '</div></div>';
	}
}
