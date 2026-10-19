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
use SentinelShield\Support\DataDir;
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

		echo '<div class="ss-card" id="ss-private"><h2>' . esc_html__( 'Private folder', 'sentinel-shield' ) . '</h2>';
		/* translators: %s: folder path. */
		echo '<p>' . esc_html( sprintf( __( 'The early firewall\'s snapshot (including allowlisted addresses), its block log and the server blocklist files are kept in %s, outside the web root, so they cannot be downloaded on any web server.', 'sentinel-shield' ), DataDir::path() ) ) . '</p>';
		if ( DataDir::ready() ) {
			$this->status( 'ok', __( 'Confirmed private and writable.', 'sentinel-shield' ) );
		} else {
			$this->status( 'bad', DataDir::problem() . ' ' . __( 'Until then, the early firewall, the server files and the block log are not written.', 'sentinel-shield' ) );
		}
		View::form_open( 'server' );
		echo '<input type="hidden" name="op" value="recheck">';
		submit_button( __( 'Re-check', 'sentinel-shield' ), 'small', 'submit', false );
		echo '</form><p class="description">' . esc_html__( 'To use another folder, add define( \'SENTINEL_SHIELD_DATA_DIR\', \'/path/outside/the/web/root\' ); to wp-config.php.', 'sentinel-shield' ) . '</p>';
		$legacy = EarlyGate::legacy_state();
		if ( ! empty( $legacy['failed'] ) ) {
			/* translators: %s: file paths. */
			$this->status( 'bad', sprintf( __( 'Files from version 0.8.0 in the public uploads folder could not be removed: %s. They may contain allowlisted addresses or visitor data; delete them by hand (removal is retried hourly).', 'sentinel-shield' ), implode( ', ', array_map( 'strval', (array) $legacy['failed'] ) ) ) );
		}
		if ( ! empty( $legacy['stubbed'] ) ) {
			/* translators: %s: file paths. */
			$this->status( 'warn', sprintf( __( 'Your server configuration may still include the old blocklist files %s. They now block nothing. Change the include lines to the files below, check and reload the web server, then delete the old files.', 'sentinel-shield' ), implode( ', ', array_map( 'strval', (array) $legacy['stubbed'] ) ) ) );
		}
		echo '</div>';

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
			/* translators: 1: generation, 2: date, 3: block count, 4: allow count, 5: feeds state, 6: date. */
			$text = sprintf( __( 'Policy generation %1$d, built %2$s: %3$d blocked ranges after removing %4$d allowlisted ones, blocklist feeds %5$s. Rebuilt after changes (at most every 10 seconds) and again after %6$s, when the next temporary rule expires; scheduled tasks can run late, so expiry reaches the other layers eventually, not to the second. WordPress itself always applies expiry immediately.', 'sentinel-shield' ), (int) ( $state['generation'] ?? 0 ), wp_date( 'Y-m-d H:i', (int) $state['built'] ), (int) $state['block'], (int) $state['allow'], ! empty( $state['feeds'] ) ? __( 'included', 'sentinel-shield' ) : __( 'not included', 'sentinel-shield' ), wp_date( 'Y-m-d H:i', (int) $state['valid_until'] ) );
			echo '<p>' . esc_html( $text ) . '</p>';
			$this->layers( $settings, $state );
			if ( isset( $state['enforcing'] ) && ! $state['enforcing'] ) {
				$this->status( 'warn', __( 'WordPress is not enforcing IP blocks (protection or the IP gate is off), so every layer gets an empty policy.', 'sentinel-shield' ) );
			}
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
		echo '<p class="description">' . esc_html( sprintf( __( 'Emergency switch-off without WordPress: create an empty file named gate.disabled in %s (or delete gate.json there). The early firewall then lets everything through to WordPress. Deactivating the plugin removes the snapshot too.', 'sentinel-shield' ), DataDir::path() ) ) . '</p></div>';

		if ( $settings->get( 'firewall.server_files', false ) ) {
			$dir = DataDir::path();
			echo '<div class="ss-card"><h2>' . esc_html__( 'Server blocklist files', 'sentinel-shield' ) . '</h2>';
			/* translators: %d: generation. */
			echo '<p>' . esc_html( sprintf( __( 'The files hold policy generation %d (your block rules minus the allowlist). The web server applies them only after a reload, and temporary rules stay there until that reload; reload often (or leave short lockouts to WordPress and the early firewall). When protection is switched off or the plugin is deactivated, the files are emptied, not deleted, so your server configuration keeps working.', 'sentinel-shield' ), (int) ( $state['generation'] ?? 0 ) ) ) . '</p><table class="widefat striped"><tbody>';
			echo '<tr><th style="width:8em">nginx</th><td><code>' . esc_html( 'include ' . $dir . '/nginx-deny.conf;' ) . '</code><br><span class="description">' . esc_html__( 'Inside the server block. Reload nginx after changes, for example every few minutes from cron: nginx -t && nginx -s reload', 'sentinel-shield' ) . '</span></td></tr>';
			echo '<tr><th>Apache 2.4</th><td><code>' . esc_html( 'Include ' . $dir . '/apache-deny.conf' ) . '</code><br><span class="description">' . esc_html__( 'Inside the virtual host or a <Directory> block of the site. Apache reads it on graceful restart.', 'sentinel-shield' ) . '</span></td></tr>';
			echo '</tbody></table></div>';
		}

		$cloudflare = $this->c->get( CloudflareSync::class );
		echo '<div class="ss-card" id="ss-cloudflare"><h2>' . esc_html__( 'Cloudflare IP list', 'sentinel-shield' ) . '</h2>';
		$sync = CloudflareSync::state();
		if ( $sync ) {
			$labels = array(
				'applying' => array( 'warn', __( 'Sent to Cloudflare, waiting for it to confirm', 'sentinel-shield' ) ),
				'active'   => array( 'ok', __( 'Active at Cloudflare', 'sentinel-shield' ) ),
				'empty'    => array( 'ok', __( 'List confirmed empty at Cloudflare', 'sentinel-shield' ) ),
				'cleared'  => array( 'ok', __( 'List emptied at Cloudflare', 'sentinel-shield' ) ),
				'failed'   => array( 'bad', __( 'Failed', 'sentinel-shield' ) ),
				'unknown'  => array( 'warn', __( 'Not confirmed by Cloudflare', 'sentinel-shield' ) ),
			);
			$label  = $labels[ (string) ( $sync['status'] ?? '' ) ] ?? ( ! empty( $sync['ok'] ) ? $labels['active'] : $labels['failed'] );
			/* translators: 1: status, 2: generation, 3: local generation, 4: count, 5: date. */
			$text = sprintf( __( '%1$s: generation %2$d (local policy: %3$d), %4$d items, %5$s.', 'sentinel-shield' ), $label[1], (int) ( $sync['generation'] ?? 0 ), (int) ( $state['generation'] ?? 0 ), (int) $sync['count'], wp_date( 'Y-m-d H:i', (int) $sync['time'] ) );
			if ( ! empty( $sync['skipped'] ) || ! empty( $sync['expanded'] ) ) {
				/* translators: 1: entries left out, 2: entries widened. */
				$text .= ' ' . sprintf( __( '%1$d entries left out (Cloudflare takes IPv6 ranges up to /64 only; WordPress still blocks them), %2$d single IPv6 addresses widened to /64.', 'sentinel-shield' ), (int) ( $sync['skipped'] ?? 0 ), (int) ( $sync['expanded'] ?? 0 ) );
			}
			if ( ! empty( $sync['error'] ) ) {
				$text .= ' ' . (string) $sync['error'];
			}
			if ( 'applying' === ( $sync['status'] ?? '' ) && 'empty' === ( $sync['want'] ?? '' ) ) {
				$label = array( 'warn', __( 'Emptying sent to Cloudflare, waiting for it to confirm', 'sentinel-shield' ) );
				$text  = $label[1] . '.';
			}
			$this->status( $label[0], $text );
			foreach ( (array) ( $sync['retired'] ?? array() ) as $old ) {
				/* translators: 1: list ID, 2: status. */
				$this->status( 'failed' === ( $old['status'] ?? '' ) ? 'bad' : 'warn', sprintf( __( 'Previous list %1$s: being emptied before it is forgotten (%2$s).', 'sentinel-shield' ), (string) ( $old['list'] ?? '' ), (string) ( $old['status'] ?? '' ) . ( empty( $old['error'] ) ? '' : ': ' . (string) $old['error'] ) ) );
			}
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
		echo '<p class="description">' . esc_html__( 'Then add a WAF custom rule in Cloudflare (Security → WAF → Custom rules) with the expression (ip.src in $your_list_name) and the action Block.', 'sentinel-shield' ) . '</p>';
		echo '<p class="description">' . esc_html__( 'Before deactivating the plugin, switch sync off here and wait until the list shows as confirmed empty. Deactivation also empties the list and waits a few seconds for Cloudflare; if Cloudflare does not confirm in that time, the site admin is emailed how to empty the list by hand (in Cloudflare: Manage Account → Configurations → Lists, or remove the WAF rule).', 'sentinel-shield' ) . '</p></div>';
	}

	/**
	 * Desired, published and confirmed policy for each layer.
	 *
	 * @param Settings             $settings Settings.
	 * @param array<string, mixed> $state    Early firewall build state.
	 */
	private function layers( Settings $settings, array $state ): void {
		$gen  = (int) ( $state['generation'] ?? 0 );
		$rows = array();
		/* translators: %d: generation. */
		$rows[ __( 'WordPress', 'sentinel-shield' ) ] = sprintf( __( 'generation %d, applied immediately', 'sentinel-shield' ), $gen );
		if ( 'off' !== $this->c->get( EarlyGate::class )->mode() ) {
			$pub = (int) ( $state['published'] ?? 0 );
			$rows[ __( 'Early firewall', 'sentinel-shield' ) ] = $pub === $gen
				/* translators: %d: generation. */
				? sprintf( __( 'generation %d published', 'sentinel-shield' ), $pub )
				/* translators: 1: generation in use, 2: wanted generation. */
				: sprintf( __( 'generation %1$d still in use; %2$d not published yet', 'sentinel-shield' ), $pub, $gen );
		}
		if ( $settings->get( 'firewall.server_files', false ) ) {
			/* translators: %d: generation. */
			$rows[ __( 'Server files', 'sentinel-shield' ) ] = sprintf( __( 'generation %d written; active only after the web server reloads', 'sentinel-shield' ), (int) ( $state['server_generation'] ?? 0 ) );
		}
		if ( $settings->get( 'cloudflare.sync', false ) ) {
			$sync = CloudflareSync::state();
			$cf   = (int) ( $sync['generation'] ?? 0 );
			$rows[ __( 'Cloudflare', 'sentinel-shield' ) ] = match ( (string) ( $sync['status'] ?? '' ) ) {
				/* translators: %d: generation. */
				'active', 'empty' => sprintf( __( 'generation %d confirmed active', 'sentinel-shield' ), $cf ),
				/* translators: %d: generation. */
				'applying'        => sprintf( __( 'generation %d sent, not confirmed yet', 'sentinel-shield' ), $cf ),
				'failed'          => __( 'last upload failed; retried every five minutes', 'sentinel-shield' ),
				'unknown'         => __( 'last upload never confirmed; it is sent again', 'sentinel-shield' ),
				default           => __( 'not synced yet', 'sentinel-shield' ),
			};
		}
		echo '<table class="widefat striped ss-narrow"><thead><tr><th>' . esc_html__( 'Layer', 'sentinel-shield' ) . '</th><th>' . esc_html__( 'Policy', 'sentinel-shield' ) . '</th></tr></thead><tbody>';
		foreach ( $rows as $layer => $text ) {
			echo '<tr><td>' . esc_html( $layer ) . '</td><td>' . esc_html( $text ) . '</td></tr>';
		}
		echo '</tbody></table>';
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
