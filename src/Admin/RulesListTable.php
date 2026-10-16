<?php
/**
 * List table for IP rules.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Admin;

use SentinelShield\Repository\BlockRepository;

defined( 'ABSPATH' ) || exit;

if ( ! class_exists( '\WP_List_Table' ) ) {
	require_once ABSPATH . 'wp-admin/includes/class-wp-list-table.php';
}

/**
 * Shows block and allow rules with reason, source, created/expiry time and hit count.
 */
final class RulesListTable extends \WP_List_Table {

	/**
	 * Constructor.
	 *
	 * @param BlockRepository $repo Rules.
	 */
	public function __construct( private BlockRepository $repo ) {
		parent::__construct(
			array(
				'singular' => 'sentinel_rule',
				'plural'   => 'sentinel_rules',
				'ajax'     => false,
			)
		);
	}

	/**
	 * Columns.
	 *
	 * @return array<string, string>
	 */
	public function get_columns(): array {
		return array(
			'cb'         => '<input type="checkbox">',
			'label'      => __( 'IP / range', 'sentinel-shield' ),
			'list_type'  => __( 'List', 'sentinel-shield' ),
			'reason'     => __( 'Reason', 'sentinel-shield' ),
			'source'     => __( 'Source', 'sentinel-shield' ),
			'created_at' => __( 'Created', 'sentinel-shield' ),
			'expires_at' => __( 'Expires', 'sentinel-shield' ),
			'hits'       => __( 'Hits', 'sentinel-shield' ),
		);
	}

	/**
	 * Sortable columns.
	 *
	 * @return array<string, array{0:string, 1:bool}>
	 */
	protected function get_sortable_columns(): array {
		return array(
			'label'      => array( 'label', false ),
			'list_type'  => array( 'list_type', false ),
			'created_at' => array( 'created_at', true ),
			'expires_at' => array( 'expires_at', false ),
			'hits'       => array( 'hits', true ),
		);
	}

	/**
	 * Bulk actions.
	 *
	 * @return array<string, string>
	 */
	protected function get_bulk_actions(): array {
		return array( 'delete' => __( 'Delete', 'sentinel-shield' ) );
	}

	/**
	 * All / Block / Allow views.
	 *
	 * @return array<string, string>
	 */
	protected function get_views(): array {
		$current = isset( $_GET['list_type'] ) ? sanitize_key( wp_unslash( $_GET['list_type'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Filter only.
		$views   = array();
		$labels  = array(
			''      => __( 'All active', 'sentinel-shield' ),
			'block' => __( 'Blocked', 'sentinel-shield' ),
			'allow' => __( 'Allowed', 'sentinel-shield' ),
		);
		foreach ( $labels as $type => $label ) {
			$count          = $this->repo->count_active( '' === $type ? null : $type );
			$url            = Admin::url( 'sentinel-shield-rules', '' === $type ? array() : array( 'list_type' => $type ) );
			$views[ '' === $type ? 'all' : $type ] = sprintf( '<a href="%1$s"%2$s>%3$s <span class="count">(%4$d)</span></a>', esc_url( $url ), $current === $type ? ' class="current" aria-current="page"' : '', esc_html( $label ), $count );
		}
		return $views;
	}

	/**
	 * Loads rows.
	 */
	public function prepare_items(): void {
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- Read-only filters.
		$per_page = 50;
		[ $rows, $total ] = $this->repo->query(
			array(
				'type'     => isset( $_GET['list_type'] ) ? sanitize_key( wp_unslash( $_GET['list_type'] ) ) : '',
				'search'   => isset( $_GET['s'] ) ? sanitize_text_field( wp_unslash( $_GET['s'] ) ) : '',
				'orderby'  => isset( $_GET['orderby'] ) ? sanitize_key( wp_unslash( $_GET['orderby'] ) ) : 'created_at',
				'order'    => isset( $_GET['order'] ) ? sanitize_key( wp_unslash( $_GET['order'] ) ) : 'desc',
				'per_page' => $per_page,
				'page'     => $this->get_pagenum(),
			)
		);
		// phpcs:enable
		$this->items           = $rows;
		$this->_column_headers = array( $this->get_columns(), array(), $this->get_sortable_columns(), 'label' );
		$this->set_pagination_args(
			array(
				'total_items' => $total,
				'per_page'    => $per_page,
			)
		);
	}

	/**
	 * Checkbox column.
	 *
	 * @param array<string, mixed> $item Row.
	 */
	protected function column_cb( $item ): string {
		return '<input type="checkbox" name="rule[]" value="' . esc_attr( (string) $item['id'] ) . '">';
	}

	/**
	 * IP column with row actions.
	 *
	 * @param array<string, mixed> $item Row.
	 */
	protected function column_label( array $item ): string {
		$delete = View::action_url( 'delete_rule', array( 'id' => (int) $item['id'] ) );
		$search = Admin::url( 'sentinel-shield-events', array( 'ip' => strtok( (string) $item['label'], '/' ) ) );
		$actions = array(
			'delete' => '<a href="' . esc_url( $delete ) . '" data-sentinel-confirm="' . esc_attr__( 'Delete this rule?', 'sentinel-shield' ) . '">' . esc_html__( 'Delete', 'sentinel-shield' ) . '</a>',
			'events' => '<a href="' . esc_url( $search ) . '">' . esc_html__( 'Events', 'sentinel-shield' ) . '</a>',
		);
		return '<code>' . esc_html( (string) $item['label'] ) . '</code>' . $this->row_actions( $actions );
	}

	/**
	 * Other columns.
	 *
	 * @param array<string, mixed> $item        Row.
	 * @param string               $column_name Column.
	 */
	protected function column_default( $item, $column_name ): string {
		switch ( $column_name ) {
			case 'list_type':
				return 'allow' === $item['list_type'] ? View::pill( __( 'allow', 'sentinel-shield' ), 'ok' ) : View::pill( __( 'block', 'sentinel-shield' ), 'bad' );
			case 'created_at':
				return esc_html( View::time( (string) $item['created_at'] ) );
			case 'expires_at':
				return empty( $item['expires_at'] ) ? esc_html__( 'Never', 'sentinel-shield' ) : esc_html( View::time( (string) $item['expires_at'] ) );
			case 'hits':
				$last = empty( $item['last_hit_at'] ) ? '' : ' <span class="description">' . esc_html( View::time( (string) $item['last_hit_at'] ) ) . '</span>';
				return esc_html( number_format_i18n( (int) $item['hits'] ) ) . $last;
			default:
				return esc_html( (string) ( $item[ $column_name ] ?? '' ) );
		}
	}

	/**
	 * Empty state.
	 */
	public function no_items(): void {
		esc_html_e( 'No rules found.', 'sentinel-shield' );
	}
}
