<?php
/**
 * Status panel on the Login Location settings tab.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Admin;

use SentinelShield\Container;
use SentinelShield\Geo\CountryList;
use SentinelShield\Geo\GeoResolver;
use SentinelShield\Geo\GeoUpdater;
use SentinelShield\Geo\LoginGeoGuard;
use SentinelShield\Settings;

defined( 'ABSPATH' ) || exit;

/**
 * Shows where the current admin is, whether they could log in again, which
 * country sources work, the database status and an IP lookup.
 */
final class GeoPanel {

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
		$guard    = $this->c->get( LoginGeoGuard::class );
		$resolver = $this->c->get( GeoResolver::class );
		$ip       = (string) $this->c->get( 'client_ip' );
		$geo      = $resolver->resolve( $ip, true );
		$check    = $guard->check( $ip, wp_get_current_user(), true );
		$mode     = (string) $settings->get( 'geo.mode', 'off' );

		echo '<div class="ss-card"><h2>' . esc_html__( 'Where you are logging in from', 'sentinel-shield' ) . '</h2>';
		echo '<p class="ss-big">' . esc_html__( 'Your IP:', 'sentinel-shield' ) . ' <code>' . esc_html( '' === $ip ? '—' : $ip ) . '</code> &nbsp; ' . esc_html__( 'Country:', 'sentinel-shield' ) . ' <strong>' . esc_html( '' === $geo['country'] ? __( 'unknown', 'sentinel-shield' ) : CountryList::label( $geo['country'] ) ) . '</strong> <span class="description">(' . esc_html( LoginGeoGuard::source_label( $geo['source'] ) ) . ')</span></p>';
		echo '<p>' . esc_html__( 'With the saved settings, a login by you from here would be:', 'sentinel-shield' ) . ' ';
		echo View::pill( $check['allowed'] ? __( 'Allowed', 'sentinel-shield' ) : __( 'Denied', 'sentinel-shield' ), $check['allowed'] ? 'ok' : 'bad' ) . ' ' . esc_html( LoginGeoGuard::explain( $check ) ) . '</p>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- pill() escapes.

		if ( ! $settings->is_module_enabled( 'geo_login' ) || ! $settings->is_enabled() ) {
			echo '<div class="notice notice-warning inline"><p>' . esc_html__( 'The "Login location restriction" module (or protection as a whole) is off on the Modules tab, so nothing is checked.', 'sentinel-shield' ) . '</p></div>';
		} elseif ( 'off' !== $mode && $settings->is_test_mode( 'geo_login' ) ) {
			echo '<div class="notice notice-info inline"><p>' . esc_html__( 'Login location is in test mode: logins that would be denied are allowed and logged as "would deny login" in the Events log.', 'sentinel-shield' ) . '</p></div>';
		}
		if ( 'off' !== $mode && ! LoginGeoGuard::countries( $settings ) ) {
			echo '<div class="notice notice-warning inline"><p>' . esc_html__( 'No countries are listed, so no login is checked.', 'sentinel-shield' ) . '</p></div>';
		}
		$db_info = $resolver->database()->info();
		if ( 'off' !== $mode && null === $db_info && '' === $resolver->cloudflare() && '' === $resolver->server_variable() ) {
			echo '<div class="notice notice-warning inline"><p>' . esc_html__( 'No country source is working: every login\'s country is unknown. Switch on the DB-IP database below, use the Cloudflare preset on the IP Detection tab if your site is behind Cloudflare, or name your server\'s country variable.', 'sentinel-shield' ) . '</p></div>';
		}

		echo '<h3>' . esc_html__( 'Country sources (used in this order)', 'sentinel-shield' ) . '</h3><table class="widefat striped ss-narrow"><tbody>';
		$cf      = $resolver->cloudflare();
		$cf_text = 'cloudflare' !== $settings->get( 'proxy.mode' )
			? __( 'Not used: the Trusted proxy preset on the IP Detection tab is not Cloudflare.', 'sentinel-shield' )
			/* translators: %s: country. */
			: ( '' === $cf ? __( 'No country header on this request.', 'sentinel-shield' ) : sprintf( __( 'Working: %s', 'sentinel-shield' ), CountryList::label( $cf ) ) );
		$this->row( __( 'Cloudflare CF-IPCountry header', 'sentinel-shield' ), '' !== $cf, $cf_text );
		$var      = (string) $settings->get( 'geo.server_var', '' );
		$var_code = $resolver->server_variable();
		$var_text = '' === $var
			? __( 'Not set.', 'sentinel-shield' )
			/* translators: 1: variable name, 2: country. */
			: ( '' === $var_code ? sprintf( __( '%s is not set to a country code on this request.', 'sentinel-shield' ), $var ) : sprintf( __( '%1$s = %2$s', 'sentinel-shield' ), $var, CountryList::label( $var_code ) ) );
		$this->row( __( 'Server variable', 'sentinel-shield' ), '' !== $var_code, $var_text );

		$state = $this->c->get( GeoUpdater::class )->state();
		if ( null !== $db_info ) {
			/* translators: 1: edition month, 2: IPv4 ranges, 3: IPv6 ranges, 4: size. */
			$db_text = sprintf( __( 'Installed: edition %1$s, %2$s IPv4 and %3$s IPv6 ranges, %4$s.', 'sentinel-shield' ), (string) ( $state['month'] ?? '?' ), number_format_i18n( $db_info['v4'] ), number_format_i18n( $db_info['v6'] ), size_format( $db_info['size'] ) );
		} else {
			$db_text = $settings->get( 'geo.dbip', false ) ? __( 'Not downloaded yet.', 'sentinel-shield' ) : __( 'Off.', 'sentinel-shield' );
		}
		if ( ! empty( $state['last_check'] ) ) {
			/* translators: %s: date. */
			$db_text .= ' ' . sprintf( __( 'Last checked %s.', 'sentinel-shield' ), wp_date( 'Y-m-d H:i', (int) $state['last_check'] ) );
		}
		if ( ! empty( $state['next_due'] ) && $settings->get( 'geo.dbip', false ) ) {
			/* translators: %s: date. */
			$db_text .= ' ' . sprintf( __( 'Next check %s.', 'sentinel-shield' ), wp_date( 'Y-m-d H:i', (int) $state['next_due'] ) );
		}
		if ( ! empty( $state['error'] ) ) {
			/* translators: %s: error. */
			$db_text .= ' ' . sprintf( __( 'Last error: %s', 'sentinel-shield' ), (string) $state['error'] );
		}
		echo '<tr><th>' . esc_html__( 'DB-IP country database', 'sentinel-shield' ) . '</th><td>' . View::pill( null !== $db_info ? __( 'Working', 'sentinel-shield' ) : __( 'Not available', 'sentinel-shield' ), null !== $db_info ? 'ok' : 'info' ) . ' ' . esc_html( $db_text ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- pill() escapes.
		if ( $settings->get( 'geo.dbip', false ) ) {
			echo '<br>';
			View::form_open( 'geo' );
			echo '<input type="hidden" name="op" value="update">';
			submit_button( __( 'Update now', 'sentinel-shield' ), 'small', 'submit', false );
			echo '</form> <a href="' . esc_url( GeoUpdater::ATTRIBUTION ) . '">' . esc_html__( 'IP Geolocation by DB-IP', 'sentinel-shield' ) . '</a>';
		}
		echo '</td></tr></tbody></table>';

		$this->lookup( $ip );

		echo '<h3>' . esc_html__( 'Good to know', 'sentinel-shield' ) . '</h3><ul class="ul-disc">';
		foreach (
			array(
				__( 'Before switching to "Allow only", add every country you and other administrators log in from, including where you travel. Mobile networks and VPNs can appear in another country.', 'sentinel-shield' ),
				__( 'If saving would deny your own next login, Login location is put into test mode automatically and you are told why.', 'sentinel-shield' ),
				__( 'Locked out by location? Add your IP to the allowlist with WP-CLI (wp sentinel allow <ip>), or add define( \'SENTINEL_SHIELD_DISABLE\', true ); to wp-config.php.', 'sentinel-shield' ),
				__( 'Already logged-in sessions are not ended when settings change. Use "Log out everyone" on the Malware Lockdown page if needed.', 'sentinel-shield' ),
				__( 'Country databases are about 98-99% accurate at country level. Treat this as one layer of protection, alongside strong passwords and two-factor authentication.', 'sentinel-shield' ),
			) as $text
		) {
			echo '<li>' . esc_html( $text ) . '</li>';
		}
		echo '</ul>';

		echo '<details><summary>' . esc_html__( 'Country codes', 'sentinel-shield' ) . '</summary><p class="ss-codes">';
		$items = array();
		foreach ( CountryList::NAMES as $code => $name ) {
			$items[] = '<code>' . esc_html( $code ) . '</code> ' . esc_html( $name );
		}
		echo implode( '<br>', $items ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped above.
		echo '</p></details></div>';
	}

	/**
	 * IP lookup form and result.
	 *
	 * @param string $ip Default IP.
	 */
	private function lookup( string $ip ): void {
		$res = View::take_result( 'geo_lookup' );
		echo '<h3>' . esc_html__( 'Look up an IP', 'sentinel-shield' ) . '</h3>';
		View::form_open( 'geo' );
		echo '<input type="hidden" name="op" value="lookup">';
		echo '<label>' . esc_html__( 'IP', 'sentinel-shield' ) . ' <input type="text" name="ip" class="regular-text code" value="' . esc_attr( is_array( $res ) ? (string) $res['ip'] : $ip ) . '" required></label> ';
		echo '<label>' . esc_html__( 'Username (optional)', 'sentinel-shield' ) . ' <input type="text" name="user" value="' . esc_attr( is_array( $res ) ? (string) $res['user'] : '' ) . '"></label> ';
		submit_button( __( 'Look up', 'sentinel-shield' ), 'secondary', 'submit', false );
		echo '</form>';
		if ( is_array( $res ) ) {
			echo '<div class="ss-result"><p><strong>' . esc_html( '' === $res['country'] ? __( 'Unknown country', 'sentinel-shield' ) : CountryList::label( (string) $res['country'] ) ) . '</strong> (' . esc_html( LoginGeoGuard::source_label( (string) $res['source'] ) ) . ')<br>';
			echo View::pill( $res['allowed'] ? __( 'Login allowed', 'sentinel-shield' ) : __( 'Login denied', 'sentinel-shield' ), $res['allowed'] ? 'ok' : 'bad' ) . ' ' . esc_html( (string) $res['explain'] ) . '</p>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- pill() escapes.
			echo '<p class="description">' . esc_html__( 'Lookups of other IPs use only the DB-IP database: the Cloudflare header and server variable describe your own request.', 'sentinel-shield' ) . '</p></div>';
		}
	}

	/**
	 * One source row.
	 *
	 * @param string $label Source.
	 * @param bool   $ok    Working.
	 * @param string $text  Details.
	 */
	private function row( string $label, bool $ok, string $text ): void {
		echo '<tr><th>' . esc_html( $label ) . '</th><td>' . View::pill( $ok ? __( 'Working', 'sentinel-shield' ) : __( 'Not available', 'sentinel-shield' ), $ok ? 'ok' : 'info' ) . ' ' . esc_html( $text ) . '</td></tr>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- pill() escapes.
	}
}
