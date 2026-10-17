<?php
/**
 * Runtime lockdown measures against the SC malware and similar takeovers.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Lockdown;

use SentinelShield\Admin\Admin;
use SentinelShield\Repository\EventRepository;
use SentinelShield\Settings;
use SentinelShield\Support\Throttle;

defined( 'ABSPATH' ) || exit;

/**
 * Each measure is a separate setting under lockdown.*. They are enforced with
 * WordPress filters, so they hold against anything that goes through WordPress
 * (including malware calling WordPress functions) but not against code that
 * edits files or the database directly; the scanner covers that side.
 */
final class Hardening {

	public const EDITOR_CAPS  = array( 'edit_plugins', 'edit_themes', 'edit_files' );
	public const INSTALL_CAPS = array( 'install_plugins', 'upload_plugins', 'install_themes', 'upload_themes' );

	/**
	 * Admin status before a capabilities change, per user (for change alerts).
	 *
	 * @var array<int, bool>
	 */
	private array $was_privileged = array();

	/**
	 * Users already alerted about in this request.
	 *
	 * @var array<int, true>
	 */
	private array $alerted = array();

	/**
	 * Constructor.
	 *
	 * @param Settings        $settings Settings.
	 * @param AdminRegistry   $admins   Administrator registry.
	 * @param EventRepository $events   Event log.
	 * @param \Closure        $ip       Returns the client IP.
	 */
	public function __construct( private Settings $settings, private AdminRegistry $admins, private EventRepository $events, private \Closure $ip ) {}

	/**
	 * Hooks the enabled measures.
	 */
	public function register(): void {
		$on = fn( string $key ): bool => (bool) $this->settings->get( 'lockdown.' . $key, false );

		if ( $on( 'disable_file_editor' ) || $on( 'block_installs' ) || $on( 'admin_lock' ) ) {
			add_filter( 'map_meta_cap', array( $this, 'map_meta_cap' ), PHP_INT_MAX, 4 );
		}
		if ( $on( 'admin_lock' ) ) {
			add_action( 'admin_init', array( $this, 'log_locked_user' ) );
			add_action( is_multisite() ? 'network_admin_notices' : 'admin_notices', array( $this, 'lock_notices' ) );
			if ( is_multisite() ) {
				add_action( 'admin_notices', array( $this, 'lock_notices' ) );
			}
		}
		if ( $on( 'block_php_uploads' ) ) {
			add_filter( 'wp_handle_upload_prefilter', array( UploadGuard::class, 'filter' ) );
			add_filter( 'wp_handle_sideload_prefilter', array( UploadGuard::class, 'filter' ) );
			add_action( 'sentinel_shield_upload_blocked', array( $this, 'log_upload' ), 10, 2 );
		}
		if ( $on( 'block_chain_rpc' ) ) {
			add_filter( 'pre_http_request', array( $this, 'filter_http' ), 0, 3 );
		}
		if ( $on( 'protect_self' ) ) {
			add_filter( 'pre_update_option_active_plugins', array( $this, 'keep_active' ), 10, 2 );
			add_filter( 'pre_update_site_option_active_sitewide_plugins', array( $this, 'keep_active_network' ), 10, 2 );
			add_action( 'deactivate_plugin', array( $this, 'guard_deactivate' ), 0 );
			add_action( 'delete_plugin', array( $this, 'guard_delete' ), 0 );
		}
		if ( $on( 'alert_admin_changes' ) ) {
			add_action( 'update_user_meta', array( $this, 'before_caps_change' ), 10, 3 );
			add_action( 'updated_user_meta', array( $this, 'after_caps_change' ), 10, 3 );
			add_action( 'added_user_meta', array( $this, 'after_caps_change' ), 10, 3 );
			add_action( 'granted_super_admin', array( $this, 'on_super_admin' ) );
		}
	}

	/**
	 * Removes file editing, installs and (for unapproved admins) every capability.
	 *
	 * @param list<string> $caps    Primitive caps required.
	 * @param string       $cap     Capability checked.
	 * @param int          $user_id User.
	 * @param array<mixed> $args    Extra args.
	 * @return list<string>
	 */
	public function map_meta_cap( array $caps, string $cap, int $user_id, array $args ): array {
		unset( $args );
		if ( $this->settings->get( 'lockdown.admin_lock', false ) && ! in_array( $cap, array( 'read', 'exist' ), true ) && $this->admins->is_locked( $user_id ) ) {
			return array( 'do_not_allow' );
		}
		if ( $this->settings->get( 'lockdown.disable_file_editor', false ) && in_array( $cap, self::EDITOR_CAPS, true ) ) {
			$caps[] = 'do_not_allow';
		}
		if ( $this->settings->get( 'lockdown.block_installs', false ) && in_array( $cap, self::INSTALL_CAPS, true ) ) {
			$caps[] = 'do_not_allow';
		}
		return $caps;
	}

	/**
	 * Logs (hourly) when a locked account uses the admin.
	 */
	public function log_locked_user(): void {
		$user_id = get_current_user_id();
		if ( $this->admins->is_locked( $user_id ) && Throttle::once( 'lockdown_denied_' . $user_id, HOUR_IN_SECONDS ) ) {
			$user = wp_get_current_user();
			$this->log(
				'lockdown_admin_denied',
				/* translators: 1: login, 2: user ID. */
				sprintf( __( 'Unapproved administrator %1$s (ID %2$d) was denied admin rights', 'sentinel-shield' ), $user->user_login, $user_id ),
				array( 'target' => $user_id )
			);
		}
	}

	/**
	 * Explains the lock to a locked user; tells approved admins about pending accounts.
	 */
	public function lock_notices(): void {
		$user_id = get_current_user_id();
		if ( $this->admins->is_locked( $user_id ) ) {
			echo '<div class="notice notice-error"><p><strong>' . esc_html__( 'Sentinel Shield:', 'sentinel-shield' ) . '</strong> ';
			printf(
				/* translators: %d: user ID. */
				esc_html__( 'Your administrator rights are suspended by the administrator lock until an approved administrator approves this account on Sentinel Shield → Malware Lockdown (or runs: wp sentinel approve-admin %d).', 'sentinel-shield' ),
				(int) $user_id
			);
			echo '</p></div>';
			return;
		}
		if ( ! current_user_can( Admin::cap() ) ) {
			return;
		}
		$screen = get_current_screen();
		if ( $screen && str_contains( (string) $screen->id, 'sentinel-shield-lockdown' ) ) {
			return;
		}
		$pending = count( $this->admins->pending() );
		if ( $pending > 0 ) {
			echo '<div class="notice notice-warning"><p><strong>' . esc_html__( 'Sentinel Shield:', 'sentinel-shield' ) . '</strong> ';
			/* translators: %d: number of accounts. */
			echo esc_html( sprintf( _n( '%d administrator account is waiting for approval and has no admin rights until then.', '%d administrator accounts are waiting for approval and have no admin rights until then.', $pending, 'sentinel-shield' ), $pending ) );
			echo ' <a href="' . esc_url( Admin::url( 'sentinel-shield-lockdown' ) . '#ss-admins' ) . '">' . esc_html__( 'Review', 'sentinel-shield' ) . '</a></p></div>';
		}
	}

	/**
	 * Logs a rejected upload.
	 *
	 * @param string $name   File name.
	 * @param string $reason Why.
	 */
	public function log_upload( string $name, string $reason ): void {
		$name = sanitize_text_field( $name );
		$this->log( 'lockdown_upload', $name . ': ' . $reason, array( 'file' => $name ) );
	}

	/**
	 * Blocks WordPress HTTP API requests to blockchain RPC gateways.
	 *
	 * @param false|array<mixed>|\WP_Error $pre  Short-circuit value.
	 * @param array<string, mixed>         $args Request arguments.
	 * @param string                       $url  URL.
	 * @return false|array<mixed>|\WP_Error
	 */
	public function filter_http( mixed $pre, array $args, string $url ): mixed {
		if ( false !== $pre ) {
			return $pre;
		}
		$why = OutboundGuard::match( $url, $args );
		if ( null === $why ) {
			return $pre;
		}
		$host = (string) wp_parse_url( $url, PHP_URL_HOST );
		if ( Throttle::once_within_budget( 'lockdown_out_' . md5( $host . $why ), 5 * MINUTE_IN_SECONDS, 'lockdown_out', 30, 5 * MINUTE_IN_SECONDS ) ) {
			$caller = self::caller();
			$this->log(
				'lockdown_outbound',
				/* translators: 1: host, 2: match reason, 3: file. */
				sprintf( __( 'Blocked request to %1$s (%2$s) from %3$s', 'sentinel-shield' ), $host, $why, '' !== $caller ? $caller : '?' ),
				array(
					'url'    => strtok( $url, '?' ),
					'match'  => $why,
					'caller' => $caller,
				)
			);
		}
		return new \WP_Error( 'sentinel_shield_blocked_outbound', __( 'Blocked by Sentinel Shield: requests to blockchain gateways are disabled on this site.', 'sentinel-shield' ) );
	}

	/**
	 * Keeps Sentinel Shield in active_plugins unless an administrator deactivated it.
	 *
	 * @param mixed $value     New value.
	 * @param mixed $old_value Old value.
	 * @return mixed
	 */
	public function keep_active( mixed $value, mixed $old_value ): mixed {
		$base = plugin_basename( SENTINEL_SHIELD_FILE );
		if ( is_array( $value ) && in_array( $base, (array) $old_value, true ) && ! in_array( $base, $value, true ) && ! $this->change_allowed() ) {
			$value[] = $base;
			$this->log_tamper( __( 'Blocked an attempt to deactivate Sentinel Shield', 'sentinel-shield' ) );
		}
		return $value;
	}

	/**
	 * Network-activation counterpart of keep_active().
	 *
	 * @param mixed $value     New value.
	 * @param mixed $old_value Old value.
	 * @return mixed
	 */
	public function keep_active_network( mixed $value, mixed $old_value ): mixed {
		$base = plugin_basename( SENTINEL_SHIELD_FILE );
		if ( is_array( $value ) && is_array( $old_value ) && isset( $old_value[ $base ] ) && ! isset( $value[ $base ] ) && ! $this->change_allowed() ) {
			$value[ $base ] = $old_value[ $base ];
			$this->log_tamper( __( 'Blocked an attempt to network-deactivate Sentinel Shield', 'sentinel-shield' ) );
		}
		return $value;
	}

	/**
	 * Stops a (non-silent) deactivation before its hooks run.
	 *
	 * @param string $plugin Plugin basename.
	 */
	public function guard_deactivate( string $plugin ): void {
		if ( plugin_basename( SENTINEL_SHIELD_FILE ) === $plugin && ! $this->change_allowed() ) {
			$this->log_tamper( __( 'Blocked an attempt to deactivate Sentinel Shield', 'sentinel-shield' ) );
			wp_die( esc_html__( 'Sentinel Shield can only be deactivated by an administrator from the Plugins screen or WP-CLI.', 'sentinel-shield' ), '', array( 'response' => 403 ) );
		}
	}

	/**
	 * Stops deletion of the plugin files unless an administrator asked for it.
	 *
	 * @param string $plugin Plugin basename.
	 */
	public function guard_delete( string $plugin ): void {
		if ( plugin_basename( SENTINEL_SHIELD_FILE ) === $plugin && ! $this->change_allowed() ) {
			$this->log_tamper( __( 'Blocked an attempt to delete Sentinel Shield', 'sentinel-shield' ) );
			wp_die( esc_html__( 'Sentinel Shield can only be deleted by an administrator from the Plugins screen or WP-CLI.', 'sentinel-shield' ), '', array( 'response' => 403 ) );
		}
	}

	/**
	 * Whether the current request may deactivate or delete this plugin: WP-CLI, or
	 * an administrator acting through the Plugins screen or an update (valid nonce).
	 */
	public function change_allowed(): bool {
		if ( ( defined( 'WP_CLI' ) && WP_CLI ) || ! file_exists( SENTINEL_SHIELD_FILE ) ) {
			return true;
		}
		if ( ! is_user_logged_in() || ! current_user_can( 'activate_plugins' ) ) {
			return false;
		}
		if ( doing_action( 'upgrader_pre_install' ) ) {
			return current_user_can( 'update_plugins' );
		}
		$base   = plugin_basename( SENTINEL_SHIELD_FILE );
		$nonces = array();
		foreach ( array( '_wpnonce', '_ajax_nonce' ) as $field ) {
			if ( isset( $_REQUEST[ $field ] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Verified below.
				$nonces[] = sanitize_text_field( wp_unslash( $_REQUEST[ $field ] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Verified below.
			}
		}
		foreach ( $nonces as $nonce ) {
			foreach ( array( 'deactivate-plugin_' . $base, 'bulk-plugins', 'updates', 'upgrade-plugin_' . $base, 'bulk-update-plugins' ) as $action ) {
				if ( wp_verify_nonce( $nonce, $action ) ) {
					return true;
				}
			}
		}
		return false;
	}

	/**
	 * Remembers whether a user was an admin before their capabilities change.
	 *
	 * @param int    $meta_id   Meta ID.
	 * @param int    $user_id   User.
	 * @param string $meta_key  Key.
	 */
	public function before_caps_change( int $meta_id, int $user_id, string $meta_key ): void {
		unset( $meta_id );
		if ( self::caps_key() === $meta_key ) {
			$user                             = get_userdata( $user_id );
			$this->was_privileged[ $user_id ] = $user instanceof \WP_User && AdminRegistry::is_privileged( $user );
		}
	}

	/**
	 * Alerts when a capabilities change makes a user an admin.
	 *
	 * @param int    $meta_id  Meta ID.
	 * @param int    $user_id  User.
	 * @param string $meta_key Key.
	 */
	public function after_caps_change( int $meta_id, int $user_id, string $meta_key ): void {
		unset( $meta_id );
		if ( self::caps_key() !== $meta_key || ! empty( $this->was_privileged[ $user_id ] ) ) {
			return;
		}
		$user = new \WP_User( $user_id );
		if ( $user->exists() && AdminRegistry::is_privileged( $user ) ) {
			$this->admin_added( $user );
		}
	}

	/**
	 * Alerts on a new super admin.
	 *
	 * @param int $user_id User.
	 */
	public function on_super_admin( int $user_id ): void {
		$user = get_userdata( $user_id );
		if ( $user instanceof \WP_User ) {
			$this->admin_added( $user );
		}
	}

	/**
	 * Logs and emails a new administrator account.
	 *
	 * @param \WP_User $user New admin.
	 */
	private function admin_added( \WP_User $user ): void {
		if ( isset( $this->alerted[ $user->ID ] ) ) {
			return;
		}
		$this->alerted[ $user->ID ] = true;
		$actor                      = wp_get_current_user();
		$by                         = $actor->exists()
			/* translators: 1: login, 2: user ID. */
			? sprintf( __( '%1$s (ID %2$d)', 'sentinel-shield' ), $actor->user_login, $actor->ID )
			: ( defined( 'WP_CLI' ) && WP_CLI ? __( 'WP-CLI', 'sentinel-shield' ) : __( 'no logged-in user (code, WP-CLI or a scheduled task)', 'sentinel-shield' ) );
		$this->log(
			'lockdown_admin_added',
			/* translators: 1: login, 2: user ID, 3: who. */
			sprintf( __( 'New administrator %1$s (ID %2$d), by %3$s', 'sentinel-shield' ), $user->user_login, $user->ID, $by ),
			array( 'target' => $user->ID )
		);
		if ( ! Throttle::once( 'lockdown_admin_mail_' . $user->ID, HOUR_IN_SECONDS ) ) {
			return;
		}
		$locked = $this->settings->get( 'lockdown.admin_lock', false ) && $this->admins->approvals() && ! $this->admins->is_approved( $user );
		$lines  = array(
			/* translators: %s: site URL. */
			sprintf( __( 'A new administrator account was created or promoted on %s.', 'sentinel-shield' ), home_url( '/' ) ),
			'',
			/* translators: %s: login. */
			sprintf( __( 'Account: %s', 'sentinel-shield' ), $user->user_login ),
			/* translators: %s: email. */
			sprintf( __( 'Email: %s', 'sentinel-shield' ), $user->user_email ),
			/* translators: %s: who. */
			sprintf( __( 'Changed by: %s', 'sentinel-shield' ), $by ),
			/* translators: %s: IP address. */
			sprintf( __( 'From IP: %s', 'sentinel-shield' ), ( $this->ip )() ),
			'',
			$locked
				? __( 'The administrator lock is on, so this account has no admin rights until you approve it:', 'sentinel-shield' )
				: __( 'If you did not expect this, remove the account and change all administrator passwords:', 'sentinel-shield' ),
			Admin::url( 'sentinel-shield-lockdown' ),
		);
		wp_mail(
			(string) get_site_option( 'admin_email' ),
			/* translators: %s: site name. */
			sprintf( __( '[%s] New administrator account', 'sentinel-shield' ), wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ) ),
			implode( "\n", $lines )
		);
	}

	/**
	 * Logs a blocked deactivation or deletion.
	 *
	 * @param string $what Description.
	 */
	private function log_tamper( string $what ): void {
		$caller = self::caller();
		$this->log( 'lockdown_tamper', $what . ( '' !== $caller ? ' (' . $caller . ')' : '' ), array( 'caller' => $caller ) );
	}

	/**
	 * Writes an event.
	 *
	 * @param string               $event   Event type.
	 * @param string               $reason  Description.
	 * @param array<string, mixed> $context Extra data.
	 */
	private function log( string $event, string $reason, array $context = array() ): void {
		$this->events->log(
			$event,
			array(
				'ip'         => ( $this->ip )(),
				'module'     => 'lockdown',
				'reason'     => $reason,
				'uri'        => isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '',
				'user_agent' => isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '',
				'user_id'    => get_current_user_id(),
				'context'    => $context,
			)
		);
	}

	/**
	 * The first file in the call stack outside WordPress core and this plugin,
	 * which shows where a blocked request or deactivation came from.
	 */
	public static function caller(): string {
		$own  = wp_normalize_path( dirname( SENTINEL_SHIELD_FILE ) ) . '/src/';
		$core = array( wp_normalize_path( ABSPATH . WPINC ) . '/', wp_normalize_path( ABSPATH . 'wp-admin' ) . '/' );
		foreach ( debug_backtrace( DEBUG_BACKTRACE_IGNORE_ARGS, 30 ) as $frame ) { // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_debug_backtrace -- Needed to name the responsible file.
			$file = wp_normalize_path( (string) ( $frame['file'] ?? '' ) );
			if ( '' === $file || str_starts_with( $file, $own ) || str_starts_with( $file, $core[0] ) || str_starts_with( $file, $core[1] ) ) {
				continue;
			}
			$root = wp_normalize_path( ABSPATH );
			return ( str_starts_with( $file, $root ) ? substr( $file, strlen( $root ) ) : $file ) . ':' . (int) ( $frame['line'] ?? 0 );
		}
		return '';
	}

	/**
	 * User meta key holding capabilities on this site.
	 */
	private static function caps_key(): string {
		global $wpdb;
		return $wpdb->get_blog_prefix() . 'capabilities';
	}
}
