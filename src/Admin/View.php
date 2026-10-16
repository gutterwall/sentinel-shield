<?php
/**
 * Shared admin rendering helpers.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Admin;

defined( 'ABSPATH' ) || exit;

/**
 * Flash notices, tool results and schema-driven form fields.
 */
final class View {

	private const FLASH  = 'sentinel_shield_flash_';
	private const RESULT = 'sentinel_shield_result_';

	/**
	 * Queues a notice for the next page load.
	 *
	 * @param string $type    success|error|warning|info.
	 * @param string $message Plain text.
	 */
	public static function flash( string $type, string $message ): void {
		$key    = self::FLASH . get_current_user_id();
		$list   = get_site_transient( $key );
		$list   = is_array( $list ) ? $list : array();
		$list[] = array( $type, $message );
		set_site_transient( $key, $list, 5 * MINUTE_IN_SECONDS );
	}

	/**
	 * Prints and clears queued notices.
	 */
	public static function render_flash(): void {
		$key  = self::FLASH . get_current_user_id();
		$list = get_site_transient( $key );
		if ( ! is_array( $list ) || ! $list ) {
			return;
		}
		delete_site_transient( $key );
		foreach ( $list as $item ) {
			$type = in_array( $item[0] ?? '', array( 'success', 'error', 'warning', 'info' ), true ) ? $item[0] : 'info';
			printf( '<div class="notice notice-%1$s is-dismissible"><p>%2$s</p></div>', esc_attr( $type ), esc_html( (string) ( $item[1] ?? '' ) ) );
		}
	}

	/**
	 * Stores a tool result for the next page load.
	 *
	 * @param string $tool Tool key.
	 * @param mixed  $data Result.
	 */
	public static function put_result( string $tool, mixed $data ): void {
		set_site_transient( self::RESULT . get_current_user_id() . '_' . $tool, $data, 5 * MINUTE_IN_SECONDS );
	}

	/**
	 * Reads and clears a tool result.
	 *
	 * @param string $tool Tool key.
	 */
	public static function take_result( string $tool ): mixed {
		$key  = self::RESULT . get_current_user_id() . '_' . $tool;
		$data = get_site_transient( $key );
		delete_site_transient( $key );
		return $data;
	}

	/**
	 * Redirects and stops.
	 *
	 * @param string $url Target.
	 */
	public static function redirect( string $url ): never {
		wp_safe_redirect( $url );
		exit;
	}

	/**
	 * Rejects the request unless the user has the capability and the nonce is valid.
	 *
	 * @param string $nonce_action Nonce action.
	 * @param string $cap          Capability.
	 */
	public static function guard( string $nonce_action, string $cap = '' ): void {
		if ( ! current_user_can( '' === $cap ? Admin::cap() : $cap ) ) {
			wp_die( esc_html__( 'You do not have permission to do that.', 'sentinel-shield' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( $nonce_action );
	}

	/**
	 * Local time for a UTC DATETIME string.
	 *
	 * @param string|null $gmt UTC datetime.
	 */
	public static function time( ?string $gmt ): string {
		if ( null === $gmt || '' === $gmt || '0000-00-00 00:00:00' === $gmt ) {
			return '';
		}
		return (string) get_date_from_gmt( $gmt, 'Y-m-d H:i:s' );
	}

	/**
	 * Form field name for a dot path, e.g. sentinel_shield[general][test_mode].
	 *
	 * @param string $key    Dot path.
	 * @param string $prefix Root name.
	 */
	public static function name( string $key, string $prefix = 'sentinel_shield' ): string {
		return $prefix . '[' . implode( '][', explode( '.', $key ) ) . ']';
	}

	/**
	 * Human-readable recommended value.
	 *
	 * @param array<string, mixed> $field Field.
	 */
	public static function recommended_text( array $field ): string {
		$rec = $field['recommended'] ?? null;
		if ( null === $rec ) {
			return '';
		}
		if ( 'checkbox' === $field['type'] ) {
			return $rec ? __( 'On', 'sentinel-shield' ) : __( 'Off', 'sentinel-shield' );
		}
		if ( 'select' === $field['type'] ) {
			return (string) ( $field['options'][ $rec ] ?? $rec );
		}
		return (string) $rec;
	}

	/**
	 * Renders a settings table row for a schema field.
	 *
	 * @param array<string, mixed> $field  Field.
	 * @param mixed                $value  Current value.
	 * @param string               $prefix Root input name.
	 */
	public static function field_row( array $field, mixed $value, string $prefix = 'sentinel_shield' ): void {
		$id   = 'ss-' . str_replace( '.', '-', (string) $field['key'] );
		$name = self::name( (string) $field['key'], $prefix );
		echo '<tr><th scope="row"><label for="' . esc_attr( $id ) . '">' . esc_html( (string) $field['label'] ) . '</label></th><td>';
		self::control( $field, $value, $id, $name );
		$rec = self::recommended_text( $field );
		if ( '' !== $rec ) {
			$ok = ( 'checkbox' === $field['type'] ? (bool) $value === (bool) $field['recommended'] : (string) $value === (string) $field['recommended'] );
			echo ' <span class="ss-badge ' . ( $ok ? 'ss-badge-ok' : 'ss-badge-rec' ) . '">';
			/* translators: %s: recommended value. */
			echo esc_html( sprintf( __( 'Recommended: %s', 'sentinel-shield' ), $rec ) );
			echo '</span>';
		}
		if ( ! empty( $field['help'] ) ) {
			echo '<p class="description">' . esc_html( (string) $field['help'] ) . '</p>';
		}
		echo '</td></tr>';
	}

	/**
	 * Renders the input control.
	 *
	 * @param array<string, mixed> $field Field.
	 * @param mixed                $value Value.
	 * @param string               $id    Element ID.
	 * @param string               $name  Input name.
	 */
	public static function control( array $field, mixed $value, string $id, string $name ): void {
		switch ( $field['type'] ) {
			case 'checkbox':
				echo '<input type="hidden" name="' . esc_attr( $name ) . '" value="0">';
				echo '<input type="checkbox" id="' . esc_attr( $id ) . '" name="' . esc_attr( $name ) . '" value="1" ' . checked( (bool) $value, true, false ) . '>';
				break;
			case 'select':
				echo '<select id="' . esc_attr( $id ) . '" name="' . esc_attr( $name ) . '">';
				foreach ( (array) $field['options'] as $opt => $label ) {
					echo '<option value="' . esc_attr( (string) $opt ) . '" ' . selected( (string) $value, (string) $opt, false ) . '>' . esc_html( (string) $label ) . '</option>';
				}
				echo '</select>';
				break;
			case 'number':
				echo '<input type="number" class="small-text" id="' . esc_attr( $id ) . '" name="' . esc_attr( $name ) . '" value="' . esc_attr( (string) (int) $value ) . '" min="' . esc_attr( (string) $field['min'] ) . '" max="' . esc_attr( (string) $field['max'] ) . '">';
				break;
			case 'textarea':
			case 'cidr_list':
				echo '<textarea class="large-text code" rows="5" id="' . esc_attr( $id ) . '" name="' . esc_attr( $name ) . '">' . esc_textarea( (string) $value ) . '</textarea>';
				break;
			default:
				echo '<input type="text" class="regular-text" id="' . esc_attr( $id ) . '" name="' . esc_attr( $name ) . '" value="' . esc_attr( (string) $value ) . '">';
		}
	}

	/**
	 * Small coloured status pill.
	 *
	 * @param string $text  Label.
	 * @param string $state ok|warn|bad|info.
	 */
	public static function pill( string $text, string $state ): string {
		return '<span class="ss-pill ss-pill-' . esc_attr( $state ) . '">' . esc_html( $text ) . '</span>';
	}

	/**
	 * Admin-post URL with a nonce.
	 *
	 * @param string               $action Action suffix.
	 * @param array<string, mixed> $args   Extra args.
	 */
	public static function action_url( string $action, array $args = array() ): string {
		return wp_nonce_url( add_query_arg( array_merge( array( 'action' => 'sentinel_shield_' . $action ), $args ), admin_url( 'admin-post.php' ) ), 'sentinel_shield_' . $action );
	}

	/**
	 * Opens an admin-post form with action and nonce fields.
	 *
	 * @param string $action    Action suffix.
	 * @param bool   $multipart File upload form.
	 */
	public static function form_open( string $action, bool $multipart = false ): void {
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '"' . ( $multipart ? ' enctype="multipart/form-data"' : '' ) . '>';
		echo '<input type="hidden" name="action" value="' . esc_attr( 'sentinel_shield_' . $action ) . '">';
		wp_nonce_field( 'sentinel_shield_' . $action );
	}
}
