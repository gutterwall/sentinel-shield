<?php
/**
 * Toolbar indicator.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Admin;

use SentinelShield\Container;
use SentinelShield\Repository\EventRepository;
use SentinelShield\Settings;

defined( 'ABSPATH' ) || exit;

/**
 * Shows requests blocked today (site time zone) and a test mode marker.
 */
final class AdminBar {

	/**
	 * Constructor.
	 *
	 * @param Container $c Services.
	 */
	public function __construct( private Container $c ) {}

	/**
	 * Hooks the node.
	 */
	public function register(): void {
		add_action( 'admin_bar_menu', array( $this, 'node' ), 100 );
	}

	/**
	 * Adds the node.
	 *
	 * @param \WP_Admin_Bar $bar Toolbar.
	 */
	public function node( \WP_Admin_Bar $bar ): void {
		$settings = $this->c->get( Settings::class );
		if ( ! is_user_logged_in() || ! current_user_can( Admin::cap() ) || ! $settings->get( 'general.admin_bar', true ) ) {
			return;
		}
		$count = get_site_transient( 'sentinel_shield_blocked_today' );
		if ( false === $count ) {
			$start = ( new \DateTimeImmutable( 'today', wp_timezone() ) )->getTimestamp();
			$count = $this->c->get( EventRepository::class )->count_since( array( 'blocked' ), $start );
			set_site_transient( 'sentinel_shield_blocked_today', $count, 5 * MINUTE_IN_SECONDS );
		}
		$title = '<span class="ab-icon dashicons dashicons-shield" aria-hidden="true"></span>'
			/* translators: %s: number of blocked requests. */
			. '<span class="ab-label">' . esc_html( sprintf( __( '%s blocked today', 'sentinel-shield' ), number_format_i18n( (int) $count ) ) ) . '</span>';
		if ( $settings->is_enabled() && $settings->global_test_mode() ) {
			$title .= ' <span class="ab-label" style="color:#f0c33c">' . esc_html__( '(test mode)', 'sentinel-shield' ) . '</span>';
		}
		$bar->add_node(
			array(
				'id'    => 'sentinel-shield',
				'title' => $title,
				'href'  => Admin::url(),
			)
		);
	}
}
