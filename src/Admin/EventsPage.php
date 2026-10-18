<?php
/**
 * Security events log.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Admin;

use SentinelShield\Container;
use SentinelShield\Repository\EventRepository;

defined( 'ABSPATH' ) || exit;

/**
 * Filterable list of blocks, would-blocks, lockouts, unlocks and config changes.
 */
final class EventsPage {

	/**
	 * Constructor.
	 *
	 * @param Container $c Services.
	 */
	public function __construct( private Container $c ) {}

	/**
	 * Known event types and labels.
	 *
	 * @return array<string, string>
	 */
	public static function types(): array {
		return array(
			'blocked'               => __( 'Blocked', 'sentinel-shield' ),
			'would_block'           => __( 'Would block (test mode)', 'sentinel-shield' ),
			'lockout'               => __( 'Lockout', 'sentinel-shield' ),
			'would_lockout'         => __( 'Would lock out (test mode)', 'sentinel-shield' ),
			'unlock'                => __( 'Unlocked', 'sentinel-shield' ),
			'unlock_requested'      => __( 'Unlock link sent', 'sentinel-shield' ),
			'unlock_limited'        => __( 'Unlock email limited', 'sentinel-shield' ),
			'unlock_refused'        => __( 'Unlock link refused', 'sentinel-shield' ),
			'unlock_revoked'        => __( 'Unlock links invalidated', 'sentinel-shield' ),
			'allowlist_auto'        => __( 'Admin IP auto-allowlisted', 'sentinel-shield' ),
			'config_change'         => __( 'Configuration change', 'sentinel-shield' ),
			'feed_updated'          => __( 'Blocklist updated', 'sentinel-shield' ),
			'feed_error'            => __( 'Blocklist update failed', 'sentinel-shield' ),
			'malware_finding'       => __( 'Malware scan finding', 'sentinel-shield' ),
			'lockdown_outbound'     => __( 'Blockchain request blocked', 'sentinel-shield' ),
			'lockdown_upload'       => __( 'Upload blocked', 'sentinel-shield' ),
			'lockdown_tamper'       => __( 'Deactivation attempt blocked', 'sentinel-shield' ),
			'lockdown_admin_added'  => __( 'New administrator', 'sentinel-shield' ),
			'lockdown_admin_denied' => __( 'Unapproved administrator denied', 'sentinel-shield' ),
			'login_denied'          => __( 'Login denied', 'sentinel-shield' ),
			'login_limit'           => __( 'Too many failed logins', 'sentinel-shield' ),
			'account_attack'        => __( 'Account under attack', 'sentinel-shield' ),
			'twofa_enabled'         => __( 'Two-factor turned on or changed', 'sentinel-shield' ),
			'twofa_disabled'        => __( 'Two-factor method removed', 'sentinel-shield' ),
			'twofa_reset'           => __( 'Two-factor reset by administrator', 'sentinel-shield' ),
			'twofa_failed'          => __( 'Wrong two-factor codes', 'sentinel-shield' ),
			'twofa_backup_used'     => __( 'Backup code used', 'sentinel-shield' ),
			'twofa_no_method'       => __( 'Two-factor login impossible', 'sentinel-shield' ),
			'would_deny_login'      => __( 'Would deny login (test mode)', 'sentinel-shield' ),
			'geo_db_updated'        => __( 'Country database updated', 'sentinel-shield' ),
			'geo_db_error'          => __( 'Country database update failed', 'sentinel-shield' ),
		);
	}

	/**
	 * Renders the page.
	 */
	public function render(): void {
		if ( ! current_user_can( Admin::cap() ) ) {
			wp_die( esc_html__( 'You do not have permission to view this page.', 'sentinel-shield' ) );
		}
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- Read-only filters.
		$filters = array(
			'event'    => isset( $_GET['event'] ) ? sanitize_key( wp_unslash( $_GET['event'] ) ) : '',
			'ip'       => isset( $_GET['ip'] ) ? sanitize_text_field( wp_unslash( $_GET['ip'] ) ) : '',
			'is_test'  => isset( $_GET['is_test'] ) ? sanitize_key( wp_unslash( $_GET['is_test'] ) ) : '',
			'page'     => isset( $_GET['paged'] ) ? max( 1, absint( $_GET['paged'] ) ) : 1,
			'per_page' => 50,
		);
		// phpcs:enable
		[ $rows, $total ] = $this->c->get( EventRepository::class )->query( $filters );
		$types            = self::types();

		echo '<div class="wrap ss-wrap"><h1>' . esc_html__( 'Security Events', 'sentinel-shield' ) . '</h1>';
		echo '<form method="get" class="ss-filters"><input type="hidden" name="page" value="sentinel-shield-events">';
		echo '<select name="event"><option value="">' . esc_html__( 'All events', 'sentinel-shield' ) . '</option>';
		foreach ( $types as $key => $label ) {
			echo '<option value="' . esc_attr( $key ) . '" ' . selected( $filters['event'], $key, false ) . '>' . esc_html( $label ) . '</option>';
		}
		echo '</select> <input type="text" name="ip" placeholder="' . esc_attr__( 'IP address', 'sentinel-shield' ) . '" value="' . esc_attr( $filters['ip'] ) . '"> ';
		echo '<select name="is_test"><option value="">' . esc_html__( 'Live and test', 'sentinel-shield' ) . '</option><option value="0" ' . selected( $filters['is_test'], '0', false ) . '>' . esc_html__( 'Live only', 'sentinel-shield' ) . '</option><option value="1" ' . selected( $filters['is_test'], '1', false ) . '>' . esc_html__( 'Test mode only', 'sentinel-shield' ) . '</option></select> ';
		submit_button( __( 'Filter', 'sentinel-shield' ), 'secondary', '', false );
		echo '</form>';

		echo '<table class="widefat striped ss-events"><thead><tr><th>' . esc_html__( 'Time', 'sentinel-shield' ) . '</th><th>' . esc_html__( 'Event', 'sentinel-shield' ) . '</th><th>' . esc_html__( 'IP', 'sentinel-shield' ) . '</th><th>' . esc_html__( 'Module', 'sentinel-shield' ) . '</th><th>' . esc_html__( 'Reason', 'sentinel-shield' ) . '</th><th>' . esc_html__( 'Request', 'sentinel-shield' ) . '</th><th>' . esc_html__( 'User agent', 'sentinel-shield' ) . '</th></tr></thead><tbody>';
		if ( ! $rows ) {
			echo '<tr><td colspan="7">' . esc_html__( 'No events yet.', 'sentinel-shield' ) . '</td></tr>';
		}
		foreach ( $rows as $row ) {
			$state = match ( (string) $row['event'] ) {
				'blocked', 'lockout' => 'bad',
				'would_block', 'would_lockout' => 'warn',
				'unlock', 'allowlist_auto' => 'ok',
				default => 'info',
			};
			$user = (int) $row['user_id'] > 0 ? get_userdata( (int) $row['user_id'] ) : false;
			echo '<tr>';
			echo '<td>' . esc_html( View::time( (string) $row['created_at'] ) ) . '</td>';
			echo '<td>' . View::pill( $types[ $row['event'] ] ?? (string) $row['event'], $state ) . '</td>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- pill() escapes.
			echo '<td>' . ( '' === $row['ip_text'] ? '—' : '<a href="' . esc_url( Admin::url( 'sentinel-shield-events', array( 'ip' => $row['ip_text'] ) ) ) . '"><code>' . esc_html( (string) $row['ip_text'] ) . '</code></a>' ) . '</td>';
			echo '<td>' . esc_html( (string) $row['module'] ) . '</td>';
			echo '<td>' . esc_html( (string) $row['reason'] ) . ( $user ? '<br><span class="description">' . esc_html( $user->user_login ) . '</span>' : '' ) . '</td>';
			echo '<td class="ss-trunc"><code>' . esc_html( (string) $row['uri'] ) . '</code></td>';
			echo '<td class="ss-trunc">' . esc_html( (string) $row['user_agent'] ) . '</td>';
			echo '</tr>';
		}
		echo '</tbody></table>';

		$pages = (int) ceil( $total / 50 );
		if ( $pages > 1 ) {
			echo '<div class="tablenav"><div class="tablenav-pages">';
			echo wp_kses_post(
				(string) paginate_links(
					array(
						'base'    => add_query_arg( 'paged', '%#%' ),
						'format'  => '',
						'current' => (int) $filters['page'],
						'total'   => $pages,
					)
				)
			);
			echo '</div></div>';
		}
		echo '</div>';
	}
}
