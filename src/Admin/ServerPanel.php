<?php
/**
 * Settings → Server & CDN: early firewall, server blocklist files, Cloudflare.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Admin;

use SentinelShield\Container;
use SentinelShield\Firewall\CloudflareSync;
use SentinelShield\Firewall\EarlyGate;
use SentinelShield\Geo\GeoUpdater;
use SentinelShield\Settings;

defined( 'ABSPATH' ) || exit;

/**
 * Status and setup help shown above the tab's settings.
 */
final class ServerPanel {

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
		$gate     = $this->c->get( EarlyGate::class );
		$state    = (array) get_site_option( EarlyGate::STATE, array() );

		echo '<div class="ss-card" id="ss-early"><h2>' . esc_html__( 'Early firewall', 'sentinel-shield' ) . '</h2>';
		$mode   = $gate->mode();
		$active = EarlyGate::active_as();
		if ( 'off' === $mode ) {
			echo '<p>' . esc_html__( 'Off: blocked IPs are refused by the normal firewall, which runs when Sentinel Shield loads, after WordPress and any plugins loaded before it.', 'sentinel-shield' ) . '</p>';
		} else {
			if ( 'prepend' === $active ) {
				$this->status( 'ok', __( 'Running before WordPress for this page (auto_prepend_file).', 'sentinel-shield' ) );
			} elseif ( 'mu' === $active ) {
				$this->status( 'prepend' === $mode ? 'warn' : 'ok', __( 'Running before other plugins for this page (must-use plugin).', 'sentinel-shield' ) );
			} else {
				$this->status( 'warn', __( 'Not running for this page yet.', 'sentinel-shield' ) . ' ' . ( 'prepend' === $mode ? __( 'Add one of the lines below to your server configuration and restart PHP.', 'sentinel-shield' ) : __( 'Reload the page; if this stays, the mu-plugins folder is not writable.', 'sentinel-shield' ) ) );
			}
			if ( 'prepend' === $mode ) {
				echo '<p>' . esc_html__( 'Add one of these lines (whichever fits your server), then restart PHP. PHP caches .user.ini for up to five minutes.', 'sentinel-shield' ) . '</p><div class="ss-scroll"><table class="widefat striped"><tbody>';
				foreach ( EarlyGate::prepend_snippets() as $where => $line ) {
					echo '<tr><th style="width:14em">' . esc_html( $where ) . '</th><td><code>' . esc_html( $line ) . '</code></td></tr>';
				}
				echo '</tbody></table></div>';
				echo '<p class="description">' . esc_html__( 'If another security plugin already uses auto_prepend_file (Wordfence does), only one file can be prepended; keep the must-use plugin option instead.', 'sentinel-shield' ) . '</p>';
			}
		}
		if ( $state ) {
			/* translators: 1: date, 2: block count, 3: allow count, 4: date. */
			$text = sprintf( __( 'Snapshot built %1$s: %2$d blocked ranges, %3$d allowlisted, blocklist feeds %5$s; used until %4$s or the next change.', 'sentinel-shield' ), wp_date( 'Y-m-d H:i', (int) $state['built'] ), (int) $state['block'], (int) $state['allow'], wp_date( 'Y-m-d H:i', (int) $state['valid_until'] ), ! empty( $state['feeds'] ) ? __( 'included', 'sentinel-shield' ) : __( 'not included', 'sentinel-shield' ) );
			echo '<p>' . esc_html( $text ) . '</p>';
			if ( ! empty( $state['error'] ) ) {
				$this->status( 'bad', (string) $state['error'] );
			}
		}
		if ( 'off' !== $mode || $settings->get( 'firewall.server_files', false ) || $settings->get( 'cloudflare.sync', false ) ) {
			View::form_open( 'server' );
			echo '<input type="hidden" name="op" value="rebuild">';
			submit_button( __( 'Rebuild now', 'sentinel-shield' ), 'secondary', 'submit', false );
			echo '</form>';
		}
		/* translators: %s: file path. */
		echo '<p class="description">' . esc_html( sprintf( __( 'Emergency switch-off without WordPress: create an empty file named gate.disabled in %s (or delete gate.json there). The early firewall then lets everything through to WordPress.', 'sentinel-shield' ), GeoUpdater::dir() ) ) . '</p></div>';

		if ( $settings->get( 'firewall.server_files', false ) ) {
			$dir = GeoUpdater::dir();
			echo '<div class="ss-card"><h2>' . esc_html__( 'Server blocklist files', 'sentinel-shield' ) . '</h2><table class="widefat striped"><tbody>';
			echo '<tr><th style="width:8em">nginx</th><td><code>' . esc_html( 'include ' . $dir . '/nginx-deny.conf;' ) . '</code><br><span class="description">' . esc_html__( 'Inside the server block. Reload nginx after changes, for example every few minutes from cron: nginx -t && nginx -s reload', 'sentinel-shield' ) . '</span></td></tr>';
			echo '<tr><th>Apache 2.4</th><td><code>' . esc_html( 'Include ' . $dir . '/apache-deny.conf' ) . '</code><br><span class="description">' . esc_html__( 'Inside the virtual host or a <Directory> block of the site. Apache reads it on graceful restart.', 'sentinel-shield' ) . '</span></td></tr>';
			echo '</tbody></table></div>';
		}

		$cloudflare = $this->c->get( CloudflareSync::class );
		echo '<div class="ss-card" id="ss-cloudflare"><h2>' . esc_html__( 'Cloudflare IP list', 'sentinel-shield' ) . '</h2>';
		$sync = CloudflareSync::state();
		if ( $sync ) {
			$this->status(
				! empty( $sync['ok'] ) ? 'ok' : 'bad',
				! empty( $sync['ok'] )
					/* translators: 1: date, 2: count. */
					? sprintf( __( 'Last sync %1$s: %2$d items.', 'sentinel-shield' ), wp_date( 'Y-m-d H:i', (int) $sync['time'] ), (int) $sync['count'] )
					/* translators: 1: date, 2: error. */
					: sprintf( __( 'Last sync %1$s failed: %2$s', 'sentinel-shield' ), wp_date( 'Y-m-d H:i', (int) $sync['time'] ), (string) $sync['error'] )
			);
		}
		View::form_open( 'server' );
		echo '<input type="hidden" name="op" value="cf_token">';
		echo '<p><label for="ss-cf-token">' . esc_html__( 'API token', 'sentinel-shield' ) . '</label><br><input type="password" class="regular-text" id="ss-cf-token" name="token" autocomplete="off" placeholder="' . esc_attr( $cloudflare->has_token() ? __( 'Stored (enter a new one to replace it)', 'sentinel-shield' ) : '' ) . '"> ';
		submit_button( __( 'Save token', 'sentinel-shield' ), 'secondary', 'submit', false );
		echo '</p><p class="description">' . esc_html__( 'Create it in Cloudflare under My Profile → API Tokens with the permission Account → Account Filter Lists → Edit. It is stored encrypted and not included in settings exports. Leave empty and save to remove it.', 'sentinel-shield' ) . '</p></form>';
		if ( $cloudflare->has_token() ) {
			echo '<p>';
			foreach ( array(
				'cf_test' => __( 'Test connection', 'sentinel-shield' ),
				'cf_sync' => __( 'Sync now', 'sentinel-shield' ),
			) as $op => $label ) {
				View::form_open( 'server' );
				echo '<input type="hidden" name="op" value="' . esc_attr( $op ) . '">';
				submit_button( $label, 'secondary', 'submit', false );
				echo '</form> ';
			}
			echo '</p>';
		}
		echo '<p class="description">' . esc_html__( 'Then add a WAF custom rule in Cloudflare (Security → WAF → Custom rules) with the expression (ip.src in $your_list_name) and the action Block.', 'sentinel-shield' ) . '</p></div>';
	}

	/**
	 * One status line.
	 *
	 * @param string $state ok, warn or bad.
	 * @param string $text  Text.
	 */
	private function status( string $state, string $text ): void {
		$labels = array(
			'ok'   => __( 'OK', 'sentinel-shield' ),
			'warn' => __( 'Check', 'sentinel-shield' ),
			'bad'  => __( 'Problem', 'sentinel-shield' ),
		);
		echo '<p>' . View::pill( $labels[ $state ], $state ) . ' ' . esc_html( $text ) . '</p>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- pill() escapes.
	}
}
