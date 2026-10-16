<?php
/**
 * Per-site overrides on multisite.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Admin;

use SentinelShield\Container;
use SentinelShield\Settings;
use SentinelShield\SettingsSchema;

defined( 'ABSPATH' ) || exit;

/**
 * Site admins may override display-only settings; IP rules stay network-wide.
 */
final class SiteSettingsPage {

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
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to view this page.', 'sentinel-shield' ) );
		}
		$settings  = $this->c->get( Settings::class );
		$network   = $settings->network_settings();
		$overrides = $settings->site_overrides();

		echo '<div class="wrap ss-wrap"><h1>' . esc_html__( 'Sentinel Shield: Site Settings', 'sentinel-shield' ) . '</h1>';
		View::render_flash();
		echo '<p>' . esc_html__( 'Security rules are managed network-wide by the network administrator. You can override how this site presents blocks.', 'sentinel-shield' ) . '</p>';
		View::form_open( 'save_site_settings' );
		echo '<table class="form-table" role="presentation">';
		foreach ( Settings::OVERRIDABLE as $key ) {
			$field = SettingsSchema::field( $key );
			if ( null === $field ) {
				continue;
			}
			$has = Settings::has_path( $overrides, $key );
			echo '<tr><th scope="row">' . esc_html( (string) $field['label'] ) . '</th><td>';
			echo '<label><input type="checkbox" name="sentinel_override[' . esc_attr( $key ) . ']" value="1" ' . checked( $has, true, false ) . '> ' . esc_html__( 'Override the network value', 'sentinel-shield' ) . '</label><br>';
			View::control( $field, $has ? Settings::get_path( $overrides, $key ) : Settings::get_path( $network, $key ), 'ss-' . str_replace( '.', '-', $key ), View::name( $key ) );
			echo '<p class="description">' . esc_html( (string) $field['help'] ) . '</p></td></tr>';
		}
		echo '</table>';
		submit_button();
		echo '</form></div>';
	}
}
