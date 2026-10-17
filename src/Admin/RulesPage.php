<?php
/**
 * IP rules page: add, list, bulk delete, import and export.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Admin;

use SentinelShield\Container;
use SentinelShield\Firewall\RuleCache;
use SentinelShield\Repository\BlockRepository;
use SentinelShield\Repository\EventRepository;

defined( 'ABSPATH' ) || exit;

/**
 * Manual allow/block lists for IPs, CIDR ranges and IPv6.
 */
final class RulesPage {

	/**
	 * Constructor.
	 *
	 * @param Container $c Services.
	 */
	public function __construct( private Container $c ) {}

	/**
	 * Handles bulk delete before output (load-{page} hook).
	 */
	public function load(): void {
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- Nonce checked with check_admin_referer below.
		$action = isset( $_GET['action'] ) ? sanitize_key( wp_unslash( $_GET['action'] ) ) : '';
		if ( '-1' === $action || '' === $action ) {
			$action = isset( $_GET['action2'] ) ? sanitize_key( wp_unslash( $_GET['action2'] ) ) : '';
		}
		if ( 'delete' !== $action || empty( $_GET['rule'] ) ) {
			return;
		}
		if ( ! current_user_can( Admin::cap() ) ) {
			wp_die( esc_html__( 'You do not have permission to do that.', 'sentinel-shield' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( 'bulk-sentinel_rules' );
		$ids = array_filter( array_map( 'absint', (array) wp_unslash( $_GET['rule'] ) ) );
		// phpcs:enable
		$repo    = $this->c->get( BlockRepository::class );
		$deleted = 0;
		foreach ( $ids as $id ) {
			$deleted += $repo->delete( $id ) ? 1 : 0;
		}
		$this->c->get( RuleCache::class )->flush();
		$this->c->get( EventRepository::class )->log(
			'config_change',
			array(
				'ip'      => (string) $this->c->get( 'client_ip' ),
				'module'  => 'core',
				'reason'  => 'rules_bulk_deleted',
				'user_id' => get_current_user_id(),
				'context' => array( 'ids' => array_values( $ids ) ),
			)
		);
		/* translators: %d: count. */
		View::flash( 'success', sprintf( _n( 'Deleted %d rule.', 'Deleted %d rules.', $deleted, 'sentinel-shield' ), $deleted ) );
		View::redirect( Admin::url( 'sentinel-shield-rules' ) );
	}

	/**
	 * Renders the page.
	 */
	public function render(): void {
		if ( ! current_user_can( Admin::cap() ) ) {
			wp_die( esc_html__( 'You do not have permission to view this page.', 'sentinel-shield' ) );
		}
		$ip    = (string) $this->c->get( 'client_ip' );
		$table = new RulesListTable( $this->c->get( BlockRepository::class ) );
		$table->prepare_items();

		echo '<div class="wrap ss-wrap"><h1>' . esc_html__( 'IP Rules', 'sentinel-shield' ) . '</h1>';
		echo '<p>' . esc_html__( 'The allowlist always wins over the blocklist and over every automatic rule. Your IP:', 'sentinel-shield' ) . ' <code>' . esc_html( $ip ) . '</code></p>';

		echo '<div class="ss-grid">';
		echo '<div class="ss-card"><h2>' . esc_html__( 'Add a rule', 'sentinel-shield' ) . '</h2>';
		View::form_open( 'add_rule' );
		echo '<p><label for="ss-value">' . esc_html__( 'IP, CIDR range or IPv6', 'sentinel-shield' ) . '</label><br><input type="text" id="ss-value" name="value" class="regular-text code" placeholder="203.0.113.7, 198.51.100.0/24, 2001:db8::/48" required></p>';
		echo '<p><label for="ss-type">' . esc_html__( 'List', 'sentinel-shield' ) . '</label><br><select id="ss-type" name="list_type"><option value="block">' . esc_html__( 'Block', 'sentinel-shield' ) . '</option><option value="allow">' . esc_html__( 'Allow (permanent allowlist)', 'sentinel-shield' ) . '</option></select></p>';
		echo '<p><label for="ss-reason">' . esc_html__( 'Reason', 'sentinel-shield' ) . '</label><br><input type="text" id="ss-reason" name="reason" class="regular-text" maxlength="255"></p>';
		echo '<p><label for="ss-exp">' . esc_html__( 'Expires after (hours, 0 = never)', 'sentinel-shield' ) . '</label><br><input type="number" id="ss-exp" name="expires_hours" value="0" min="0" class="small-text"></p>';
		submit_button( __( 'Add rule', 'sentinel-shield' ), 'primary', 'submit', false );
		echo '</form></div>';

		echo '<div class="ss-card"><h2>' . esc_html__( 'Import / export', 'sentinel-shield' ) . '</h2>';
		echo '<p><a class="button" href="' . esc_url( View::action_url( 'export_rules' ) ) . '">' . esc_html__( 'Export CSV', 'sentinel-shield' ) . '</a></p>';
		View::form_open( 'import_rules', true );
		echo '<p><label for="ss-csv">' . esc_html__( 'Import CSV or text list', 'sentinel-shield' ) . '</label><br><input type="file" id="ss-csv" name="sentinel_csv" accept=".csv,.txt,.netset,.ipset,text/csv,text/plain" required></p>';
		echo '<p class="description">' . esc_html__( 'Columns: value, list_type (block|allow), reason, expires_at (UTC, empty = never). Files exported here can be re-imported. A plain list with one IP or CIDR per line ("#" comments allowed) is imported as block rules. Up to 10,000 lines; rows that would block your own IP are skipped. Public blocklists can be kept up to date automatically on Settings → Blocklists.', 'sentinel-shield' ) . '</p>';
		submit_button( __( 'Import', 'sentinel-shield' ), 'secondary', 'submit', false );
		echo '</form></div>';
		echo '</div>';

		echo '<form method="get">';
		echo '<input type="hidden" name="page" value="sentinel-shield-rules">';
		if ( isset( $_GET['list_type'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Filter passthrough.
			echo '<input type="hidden" name="list_type" value="' . esc_attr( sanitize_key( wp_unslash( $_GET['list_type'] ) ) ) . '">'; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		}
		$table->views();
		$table->search_box( __( 'Search IP or reason', 'sentinel-shield' ), 'ss-rule-search' );
		$table->display();
		echo '</form></div>';
	}
}
