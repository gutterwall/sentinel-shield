<?php
/**
 * admin-post.php handlers. Every handler checks capability and nonce first.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Admin;

use SentinelShield\Container;
use SentinelShield\Firewall\BlockPage;
use SentinelShield\Firewall\Decision;
use SentinelShield\Firewall\Gate;
use SentinelShield\Firewall\RuleCache;
use SentinelShield\Lockout\Unblocker;
use SentinelShield\Modules\LockoutModule;
use SentinelShield\Modules\MaintenanceModule;
use SentinelShield\Net\Cidr;
use SentinelShield\Net\ClientIpFactory;
use SentinelShield\Net\CloudflareRanges;
use SentinelShield\Repository\BlockRepository;
use SentinelShield\Repository\EventRepository;
use SentinelShield\Safety\AdminProtection;
use SentinelShield\Settings;
use SentinelShield\SettingsSchema;
use SentinelShield\Unlock\UnlockService;

defined( 'ABSPATH' ) || exit;

/**
 * Form and link handlers for the admin UI.
 */
final class Actions {

	/**
	 * Constructor.
	 *
	 * @param Container $c Services.
	 */
	public function __construct( private Container $c ) {}

	/**
	 * Hooks handlers.
	 */
	public function register(): void {
		$map = array(
			'save_settings'      => 'save_settings',
			'save_site_settings' => 'save_site_settings',
			'add_rule'           => 'add_rule',
			'delete_rule'        => 'delete_rule',
			'unblock_ip'         => 'unblock_ip',
			'export_rules'       => 'export_rules',
			'import_rules'       => 'import_rules',
			'export_settings'    => 'export_settings',
			'import_settings'    => 'import_settings',
			'tool'               => 'tool',
			'preview_block'      => 'preview_block',
			'dismiss_welcome'    => 'dismiss_welcome',
		);
		foreach ( $map as $action => $method ) {
			add_action( 'admin_post_sentinel_shield_' . $action, array( $this, $method ) );
		}
	}

	/**
	 * Current admin's IP.
	 */
	private function ip(): string {
		return (string) $this->c->get( 'client_ip' );
	}

	/**
	 * Allowlists the admin's IP and warns if it matches a block rule.
	 */
	private function protect_admin(): void {
		$protection = $this->c->get( AdminProtection::class );
		$ip         = $this->ip();
		if ( '' === $ip ) {
			return;
		}
		if ( $protection->ensure_allowlisted( $ip, get_current_user_id() ) ) {
			/* translators: %s: IP address. */
			View::flash( 'info', sprintf( __( 'Your IP %s was added to the permanent allowlist so you cannot lock yourself out.', 'sentinel-shield' ), $ip ) );
		}
		$decision = $protection->self_check( $ip );
		if ( null !== $decision ) {
			/* translators: 1: IP address, 2: rule. */
			View::flash( 'warning', sprintf( __( 'Warning: your IP %1$s matches block rule %2$s. You are only allowed in because of the allowlist.', 'sentinel-shield' ), $ip, (string) ( $decision->rule['label'] ?? '' ) ) );
		}
	}

	/**
	 * Logs a configuration change.
	 *
	 * @param string               $what    Short description.
	 * @param array<string, mixed> $context Extra data.
	 */
	private function audit( string $what, array $context = array() ): void {
		$this->c->get( EventRepository::class )->log(
			'config_change',
			array(
				'ip'      => $this->ip(),
				'module'  => 'core',
				'reason'  => $what,
				'user_id' => get_current_user_id(),
				'context' => $context,
			)
		);
	}

	/**
	 * Saves one settings tab.
	 */
	public function save_settings(): void {
		View::guard( 'sentinel_shield_save_settings' );
		$tabs = SettingsSchema::tabs();
		$tab  = isset( $_POST['tab'] ) ? sanitize_key( wp_unslash( $_POST['tab'] ) ) : 'general';
		$tab  = isset( $tabs[ $tab ] ) ? $tab : 'general';
		// Values are sanitized per field by SettingsSchema::sanitize_field().
		$input = isset( $_POST['sentinel_shield'] ) && is_array( $_POST['sentinel_shield'] ) ? wp_unslash( $_POST['sentinel_shield'] ) : array(); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized

		$settings           = $this->c->get( Settings::class );
		[ $new, $errors ]   = SettingsSchema::sanitize_tab( $tab, $input, $settings->network_settings() );
		if ( 'general' === $tab ) {
			$new = Settings::apply_test_mode_expiry( $new );
		}
		$settings->save_network( $new );
		$this->audit( 'settings:' . $tab );
		foreach ( $errors as $error ) {
			View::flash( 'error', $error );
		}
		View::flash( 'success', __( 'Settings saved.', 'sentinel-shield' ) );
		$this->protect_admin();
		View::redirect( Admin::url( 'sentinel-shield-settings', array( 'tab' => $tab ) ) );
	}

	/**
	 * Saves per-site overrides (multisite).
	 */
	public function save_site_settings(): void {
		View::guard( 'sentinel_shield_save_site_settings', 'manage_options' );
		$settings  = $this->c->get( Settings::class );
		$overrides = $settings->site_overrides();
		$input     = isset( $_POST['sentinel_shield'] ) && is_array( $_POST['sentinel_shield'] ) ? wp_unslash( $_POST['sentinel_shield'] ) : array(); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Sanitized per field below.
		$enabled   = isset( $_POST['sentinel_override'] ) && is_array( $_POST['sentinel_override'] ) ? array_map( 'sanitize_text_field', wp_unslash( $_POST['sentinel_override'] ) ) : array();

		foreach ( Settings::OVERRIDABLE as $key ) {
			$field = SettingsSchema::field( $key );
			if ( null === $field ) {
				continue;
			}
			if ( empty( $enabled[ $key ] ) ) {
				Settings::unset_path( $overrides, $key );
				continue;
			}
			[ $value ] = SettingsSchema::sanitize_field( $field, Settings::get_path( $input, $key, 'checkbox' === $field['type'] ? false : '' ) );
			Settings::set_path( $overrides, $key, $value );
		}
		$settings->save_site_overrides( $overrides );
		View::flash( 'success', __( 'Site settings saved.', 'sentinel-shield' ) );
		View::redirect( admin_url( 'admin.php?page=sentinel-shield-site' ) );
	}

	/**
	 * Adds an allow or block rule.
	 */
	public function add_rule(): void {
		View::guard( 'sentinel_shield_add_rule' );
		$value  = isset( $_POST['value'] ) ? sanitize_text_field( wp_unslash( $_POST['value'] ) ) : '';
		$type   = isset( $_POST['list_type'] ) && 'allow' === $_POST['list_type'] ? 'allow' : 'block';
		$reason = isset( $_POST['reason'] ) ? sanitize_text_field( wp_unslash( $_POST['reason'] ) ) : '';
		$hours  = isset( $_POST['expires_hours'] ) ? max( 0, absint( $_POST['expires_hours'] ) ) : 0;
		$back   = Admin::url( 'sentinel-shield-rules' );
		$cidr   = Cidr::parse( $value );

		if ( null === $cidr ) {
			/* translators: %s: input. */
			View::flash( 'error', sprintf( __( '"%s" is not a valid IP address or CIDR range.', 'sentinel-shield' ), $value ) );
			View::redirect( $back );
		}
		if ( 'block' === $type && AdminProtection::covers( $cidr, $this->ip() ) ) {
			/* translators: %s: IP address. */
			View::flash( 'error', sprintf( __( 'Refused: this rule would block your own IP (%s). Use WP-CLI if you really need it.', 'sentinel-shield' ), $this->ip() ) );
			View::redirect( $back );
		}
		$id = $this->c->get( BlockRepository::class )->add(
			$type,
			$cidr,
			'' === $reason ? __( 'Added manually', 'sentinel-shield' ) : $reason,
			'manual',
			$hours > 0 ? time() + ( $hours * HOUR_IN_SECONDS ) : null,
			get_current_user_id()
		);
		$this->c->get( RuleCache::class )->flush();
		$this->audit(
			'rule_added',
			array(
				'id'   => $id,
				'type' => $type,
				'rule' => $cidr->to_string(),
			)
		);
		/* translators: 1: list type, 2: IP or range. */
		View::flash( 'success', sprintf( __( 'Added %1$s rule for %2$s.', 'sentinel-shield' ), $type, $cidr->to_string() ) );
		View::redirect( $back );
	}

	/**
	 * Deletes one rule.
	 */
	public function delete_rule(): void {
		View::guard( 'sentinel_shield_delete_rule' );
		$id   = isset( $_GET['id'] ) ? absint( $_GET['id'] ) : 0;
		$repo = $this->c->get( BlockRepository::class );
		$rule = $repo->get( $id );
		if ( null !== $rule && $repo->delete( $id ) ) {
			$this->c->get( RuleCache::class )->flush();
			$this->audit(
				'rule_removed',
				array(
					'id'   => $id,
					'rule' => $rule['label'],
					'type' => $rule['list_type'],
				)
			);
			/* translators: %s: rule. */
			View::flash( 'success', sprintf( __( 'Removed rule %s.', 'sentinel-shield' ), (string) $rule['label'] ) );
		}
		View::redirect( Admin::url( 'sentinel-shield-rules' ) );
	}

	/**
	 * Unblocks an IP (single-IP blocks removed, optional temporary allow).
	 */
	public function unblock_ip(): void {
		View::guard( 'sentinel_shield_unblock_ip' );
		$ip     = isset( $_POST['ip'] ) ? sanitize_text_field( wp_unslash( $_POST['ip'] ) ) : '';
		$ranges = ! empty( $_POST['include_ranges'] );
		$hours  = isset( $_POST['allow_hours'] ) ? absint( $_POST['allow_hours'] ) : 0;
		$result = $this->c->get( Unblocker::class )->unblock( $ip, $ranges, $hours, get_current_user_id(), 'admin' );
		if ( null === $result ) {
			View::flash( 'error', __( 'Enter a single valid IP address.', 'sentinel-shield' ) );
		} else {
			/* translators: 1: count, 2: IP address. */
			View::flash( 'success', sprintf( __( 'Removed %1$d block rule(s) for %2$s.', 'sentinel-shield' ), $result['removed'], $ip ) );
			if ( $result['ranges'] ) {
				/* translators: %s: list of ranges. */
				View::flash( 'warning', sprintf( __( 'Range blocks still cover this IP: %s. Tick "also remove ranges" or add a temporary allow.', 'sentinel-shield' ), implode( ', ', $result['ranges'] ) ) );
			}
		}
		View::redirect( Admin::url( 'sentinel-shield-tools' ) );
	}

	/**
	 * Neutralizes spreadsheet formula injection in CSV cells.
	 *
	 * @param mixed $value Cell.
	 */
	private static function csv_cell( mixed $value ): string {
		$value = (string) $value;
		return ( '' !== $value && in_array( $value[0], array( '=', '+', '-', '@', "\t", "\r" ), true ) ) ? "'" . $value : $value;
	}

	/**
	 * Streams rules as CSV.
	 */
	public function export_rules(): void {
		View::guard( 'sentinel_shield_export_rules' );
		[ $rows ] = $this->c->get( BlockRepository::class )->query(
			array(
				'per_page' => 1000000,
				'orderby'  => 'list_type',
				'order'    => 'ASC',
			)
		);
		nocache_headers();
		header( 'Content-Type: text/csv; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="sentinel-shield-rules-' . gmdate( 'Ymd-His' ) . '.csv"' );
		$out = fopen( 'php://output', 'w' ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- Streaming to output.
		fputcsv( $out, array( 'value', 'list_type', 'reason', 'source', 'created_at_utc', 'expires_at_utc', 'hits' ) );
		foreach ( $rows as $row ) {
			fputcsv( $out, array_map( array( self::class, 'csv_cell' ), array( $row['label'], $row['list_type'], $row['reason'], $row['source'], $row['created_at'], (string) $row['expires_at'], $row['hits'] ) ) );
		}
		fclose( $out ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
		exit;
	}

	/**
	 * Imports rules from CSV: value, list_type, reason, [source], [created], expires_at_utc.
	 */
	public function import_rules(): void {
		View::guard( 'sentinel_shield_import_rules' );
		$back = Admin::url( 'sentinel-shield-rules' );
		$file = isset( $_FILES['sentinel_csv'] ) && is_array( $_FILES['sentinel_csv'] ) ? $_FILES['sentinel_csv'] : null; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- Validated below.
		if ( null === $file || UPLOAD_ERR_OK !== (int) $file['error'] || ! is_uploaded_file( (string) $file['tmp_name'] ) || (int) $file['size'] > 2 * MB_IN_BYTES ) {
			View::flash( 'error', __( 'Upload a CSV file up to 2 MB.', 'sentinel-shield' ) );
			View::redirect( $back );
		}
		$handle = fopen( (string) $file['tmp_name'], 'r' ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen
		if ( false === $handle ) {
			View::redirect( $back );
		}
		$repo     = $this->c->get( BlockRepository::class );
		$admin_ip = $this->ip();
		$added    = 0;
		$skipped  = 0;
		$line     = 0;
		while ( false !== ( $row = fgetcsv( $handle ) ) && $line < 10000 ) { // phpcs:ignore Generic.CodeAnalysis.AssignmentInCondition.FoundInWhileCondition
			++$line;
			$value = trim( ltrim( (string) ( $row[0] ?? '' ), "'" ) );
			if ( 1 === $line && 'value' === strtolower( $value ) ) {
				continue;
			}
			$cidr = Cidr::parse( $value );
			$type = 'allow' === strtolower( trim( (string) ( $row[1] ?? 'block' ) ) ) ? 'allow' : 'block';
			if ( null === $cidr || ( 'block' === $type && AdminProtection::covers( $cidr, $admin_ip ) ) ) {
				++$skipped;
				continue;
			}
			$expires_text = trim( (string) ( $row[5] ?? ( $row[3] ?? '' ) ) );
			$expires      = '' === $expires_text ? null : strtotime( $expires_text . ' UTC' );
			if ( false === $expires || ( null !== $expires && $expires <= time() ) ) {
				++$skipped;
				continue;
			}
			$repo->add( $type, $cidr, sanitize_text_field( ltrim( (string) ( $row[2] ?? '' ), "'" ) ), 'import', $expires, get_current_user_id() );
			++$added;
		}
		fclose( $handle ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
		$this->c->get( RuleCache::class )->flush();
		$this->audit(
			'rules_imported',
			array(
				'added'   => $added,
				'skipped' => $skipped,
			)
		);
		/* translators: 1: added count, 2: skipped count. */
		View::flash( 'success', sprintf( __( 'Imported %1$d rule(s); skipped %2$d invalid, expired or self-blocking row(s).', 'sentinel-shield' ), $added, $skipped ) );
		View::redirect( $back );
	}

	/**
	 * Downloads settings as JSON.
	 */
	public function export_settings(): void {
		View::guard( 'sentinel_shield_export_settings' );
		$data = array(
			'plugin'   => 'sentinel-shield',
			'version'  => SENTINEL_SHIELD_VERSION,
			'exported' => gmdate( 'c' ),
			'settings' => $this->c->get( Settings::class )->network_settings(),
		);
		nocache_headers();
		header( 'Content-Type: application/json; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="sentinel-shield-settings-' . gmdate( 'Ymd-His' ) . '.json"' );
		echo wp_json_encode( $data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- JSON download.
		exit;
	}

	/**
	 * Imports settings from an uploaded or pasted JSON document.
	 */
	public function import_settings(): void {
		View::guard( 'sentinel_shield_import_settings' );
		$back = Admin::url( 'sentinel-shield-tools' );
		$json = '';
		$file = isset( $_FILES['sentinel_json'] ) && is_array( $_FILES['sentinel_json'] ) ? $_FILES['sentinel_json'] : null; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- Validated below.
		if ( null !== $file && UPLOAD_ERR_OK === (int) $file['error'] && is_uploaded_file( (string) $file['tmp_name'] ) && (int) $file['size'] <= 256 * KB_IN_BYTES ) {
			$json = (string) file_get_contents( (string) $file['tmp_name'] ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		} elseif ( ! empty( $_POST['sentinel_json_text'] ) ) {
			$json = (string) wp_unslash( $_POST['sentinel_json_text'] ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Decoded and sanitized per field.
		}
		$data = json_decode( $json, true );
		if ( ! is_array( $data ) ) {
			View::flash( 'error', __( 'That is not valid JSON.', 'sentinel-shield' ) );
			View::redirect( $back );
		}
		$raw                = isset( $data['settings'] ) && is_array( $data['settings'] ) ? $data['settings'] : $data;
		[ $clean, $errors ] = SettingsSchema::sanitize_all( $raw );
		$this->c->get( Settings::class )->save_network( $clean );
		$this->audit( 'settings_imported' );
		foreach ( $errors as $error ) {
			View::flash( 'error', $error );
		}
		View::flash( 'success', __( 'Settings imported. Unknown keys were ignored and missing keys reset to defaults.', 'sentinel-shield' ) );
		$this->protect_admin();
		View::redirect( $back );
	}

	/**
	 * Testing and maintenance tools.
	 */
	public function tool(): void {
		View::guard( 'sentinel_shield_tool' );
		$tool     = isset( $_POST['tool'] ) ? sanitize_key( wp_unslash( $_POST['tool'] ) ) : '';
		$back     = Admin::url( 'sentinel-shield-tools' );
		$settings = $this->c->get( Settings::class );

		switch ( $tool ) {
			case 'test_mode':
				$mode = isset( $_POST['mode'] ) ? sanitize_key( wp_unslash( $_POST['mode'] ) ) : '';
				$all  = $settings->network_settings();
				$all['general']['test_mode']       = in_array( $mode, array( 'on', 'on24' ), true );
				$all['general']['test_mode_hours'] = 'on24' === $mode ? 24 : 0;
				$settings->save_network( Settings::apply_test_mode_expiry( $all ) );
				$this->audit( 'test_mode:' . $mode );
				$this->protect_admin();
				View::flash( 'success', 'off' === $mode ? __( 'Test mode is off. Blocking is now enforced.', 'sentinel-shield' ) : __( 'Test mode is on. Nothing will be blocked.', 'sentinel-shield' ) );
				break;

			case 'simulate':
				$ip     = isset( $_POST['ip'] ) ? sanitize_text_field( wp_unslash( $_POST['ip'] ) ) : '';
				$uri    = isset( $_POST['uri'] ) ? sanitize_text_field( wp_unslash( $_POST['uri'] ) ) : '/';
				$ignore = ! empty( $_POST['ignore_allowlist'] );
				$gate   = $this->c->get( Gate::class );
				$d      = $gate->evaluate( $ip, '' === $uri ? '/' : $uri, $ignore, true );
				View::put_result(
					'simulate',
					array(
						'ip'       => $ip,
						'uri'      => $uri,
						'action'   => $d->action,
						'reason'   => $d->reason,
						'rule'     => (string) ( $d->rule['label'] ?? '' ),
						'source'   => (string) ( $d->rule['source'] ?? '' ),
						'enforced' => $d->is_block() && ! $gate->is_test_for_source( (string) ( $d->rule['source'] ?? 'manual' ) ),
						'enabled'  => $settings->is_enabled() && $settings->is_module_enabled( 'ip_gate' ),
					)
				);
				break;

			case 'resolve':
				$remote  = isset( $_POST['remote_addr'] ) ? sanitize_text_field( wp_unslash( $_POST['remote_addr'] ) ) : '';
				$headers = isset( $_POST['headers'] ) ? sanitize_textarea_field( wp_unslash( $_POST['headers'] ) ) : '';
				$mode    = isset( $_POST['mode'] ) ? sanitize_key( wp_unslash( $_POST['mode'] ) ) : '';
				$server  = array( 'REMOTE_ADDR' => $remote );
				foreach ( preg_split( '/\R/', $headers ) ?: array() as $line ) {
					$parts = explode( ':', $line, 2 );
					if ( 2 === count( $parts ) && '' !== trim( $parts[0] ) ) {
						$server[ 'HTTP_' . strtoupper( str_replace( '-', '_', trim( $parts[0] ) ) ) ] = trim( $parts[1] );
					}
				}
				$proxy = (array) $settings->get( 'proxy' );
				if ( in_array( $mode, array( 'none', 'cloudflare', 'load_balancer', 'custom' ), true ) ) {
					$proxy['mode'] = $mode;
				}
				View::put_result(
					'resolve',
					array(
						'input'   => array(
							'remote_addr' => $remote,
							'headers'     => $headers,
							'mode'        => $proxy['mode'],
						),
						'details' => $this->c->get( ClientIpFactory::class )->create( $server, $proxy )->details(),
					)
				);
				break;

			case 'lockout':
				$ip     = isset( $_POST['ip'] ) ? sanitize_text_field( wp_unslash( $_POST['ip'] ) ) : '';
				$module = isset( $_POST['module'] ) ? sanitize_key( wp_unslash( $_POST['module'] ) ) : 'test';
				if ( ! $settings->is_module_enabled( 'lockout' ) || ! $settings->is_enabled() ) {
					View::flash( 'error', __( 'The lockout module is disabled.', 'sentinel-shield' ) );
					break;
				}
				$lockout = LockoutModule::apply( $this->c, $ip, '' === $module ? 'test' : $module, __( 'Manual lockout from Tools (testing)', 'sentinel-shield' ) );
				View::put_result(
					'lockout',
					null === $lockout ? array( 'ip' => $ip ) : array(
						'ip'       => $lockout->ip,
						'step'     => $lockout->step,
						'duration' => $lockout->duration,
						'expires'  => $lockout->expires,
						'is_test'  => $lockout->is_test,
					)
				);
				break;

			case 'send_unlock':
				$user = wp_get_current_user();
				$this->c->get( UnlockService::class )->send_link( $user, $this->ip(), true );
				/* translators: %s: email address. */
				View::flash( 'success', sprintf( __( 'An unlock link was emailed to %s. Opening it will allowlist your IP temporarily.', 'sentinel-shield' ), $user->user_email ) );
				break;

			case 'flush_cache':
				$this->c->get( RuleCache::class )->flush();
				View::flash( 'success', __( 'Rule cache cleared.', 'sentinel-shield' ) );
				break;

			case 'maintenance':
				$result = MaintenanceModule::run( $this->c );
				/* translators: %s: JSON summary. */
				View::flash( 'success', sprintf( __( 'Housekeeping done: %s', 'sentinel-shield' ), (string) wp_json_encode( $result ) ) );
				break;

			case 'cf_refresh':
				$result = $this->c->get( CloudflareRanges::class )->refresh();
				if ( is_wp_error( $result ) ) {
					View::flash( 'error', $result->get_error_message() );
				} else {
					View::flash( 'success', __( 'Cloudflare IP ranges updated.', 'sentinel-shield' ) );
				}
				$back = isset( $_POST['back'] ) && 'ip' === $_POST['back'] ? Admin::url( 'sentinel-shield-settings', array( 'tab' => 'ip_detection' ) ) : $back;
				break;

			default:
				View::flash( 'error', __( 'Unknown tool.', 'sentinel-shield' ) );
		}
		View::redirect( $back );
	}

	/**
	 * Renders the block page for the admin without blocking them.
	 */
	public function preview_block(): void {
		View::guard( 'sentinel_shield_preview_block' );
		$decision = new Decision( Decision::BLOCK, __( 'Example reason: too many failed logins', 'sentinel-shield' ), 'ip_gate' );
		nocache_headers();
		echo BlockPage::html( $decision, $this->c->get( Settings::class ), $this->ip(), '', true ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped inside html().
		exit;
	}

	/**
	 * Hides the first-run notice.
	 */
	public function dismiss_welcome(): void {
		View::guard( 'sentinel_shield_dismiss_welcome' );
		delete_site_option( 'sentinel_shield_welcome' );
		View::redirect( wp_get_referer() ? wp_get_referer() : Admin::url() );
	}
}
