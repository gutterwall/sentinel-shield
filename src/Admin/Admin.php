<?php
/**
 * Admin menus, assets and notices.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Admin;

use SentinelShield\Container;
use SentinelShield\Firewall\RuleCache;
use SentinelShield\Net\IpAddress;
use SentinelShield\Safety\AdminProtection;
use SentinelShield\Safety\SafetyGuard;
use SentinelShield\Settings;

defined( 'ABSPATH' ) || exit;

/**
 * On multisite the full UI lives in Network Admin (manage_network_options);
 * each site gets a small page for the overridable display settings (manage_options).
 */
final class Admin {

	public const SLUG = 'sentinel-shield';

	/**
	 * Constructor.
	 *
	 * @param Container $c Services.
	 */
	public function __construct( private Container $c ) {}

	/**
	 * Capability for network-level (or single-site) administration.
	 */
	public static function cap(): string {
		return is_multisite() ? 'manage_network_options' : 'manage_options';
	}

	/**
	 * URL of one of the plugin's admin pages.
	 *
	 * @param string               $page Page slug.
	 * @param array<string, mixed> $args Extra query args.
	 */
	public static function url( string $page = self::SLUG, array $args = array() ): string {
		$base = is_multisite() ? network_admin_url( 'admin.php' ) : admin_url( 'admin.php' );
		return add_query_arg( array_merge( array( 'page' => $page ), $args ), $base );
	}

	/**
	 * Hooks everything.
	 */
	public function register(): void {
		add_action( is_multisite() ? 'network_admin_menu' : 'admin_menu', array( $this, 'menus' ) );
		if ( is_multisite() ) {
			add_action( 'admin_menu', array( $this, 'site_menu' ) );
		}
		add_action( 'admin_enqueue_scripts', array( $this, 'assets' ) );
		add_action( is_multisite() ? 'network_admin_notices' : 'admin_notices', array( $this, 'notices' ) );
		add_filter( ( is_multisite() ? 'network_admin_' : '' ) . 'plugin_action_links_' . plugin_basename( SENTINEL_SHIELD_FILE ), array( $this, 'action_links' ) );
		( new Actions( $this->c ) )->register();
	}

	/**
	 * Network (or single-site) menus.
	 */
	public function menus(): void {
		$cap       = self::cap();
		$dashboard = new DashboardPage( $this->c );
		add_menu_page( __( 'Sentinel Shield', 'sentinel-shield' ), __( 'Sentinel Shield', 'sentinel-shield' ), $cap, self::SLUG, array( $dashboard, 'render' ), 'dashicons-shield', 80 );
		add_submenu_page( self::SLUG, __( 'Dashboard', 'sentinel-shield' ), __( 'Dashboard', 'sentinel-shield' ), $cap, self::SLUG, array( $dashboard, 'render' ) );
		add_submenu_page( self::SLUG, __( 'Settings', 'sentinel-shield' ), __( 'Settings', 'sentinel-shield' ), $cap, 'sentinel-shield-settings', array( new SettingsPage( $this->c ), 'render' ) );
		$rules = new RulesPage( $this->c );
		$hook  = add_submenu_page( self::SLUG, __( 'IP Rules', 'sentinel-shield' ), __( 'IP Rules', 'sentinel-shield' ), $cap, 'sentinel-shield-rules', array( $rules, 'render' ) );
		if ( is_string( $hook ) ) {
			add_action( 'load-' . $hook, array( $rules, 'load' ) );
		}
		add_submenu_page( self::SLUG, __( 'Events', 'sentinel-shield' ), __( 'Events', 'sentinel-shield' ), $cap, 'sentinel-shield-events', array( new EventsPage( $this->c ), 'render' ) );
		add_submenu_page( self::SLUG, __( 'Malware Lockdown', 'sentinel-shield' ), __( 'Malware Lockdown', 'sentinel-shield' ), $cap, 'sentinel-shield-lockdown', array( new LockdownPage( $this->c ), 'render' ) );
		add_submenu_page( self::SLUG, __( 'Scheduled Tasks', 'sentinel-shield' ), __( 'Scheduled Tasks', 'sentinel-shield' ), $cap, 'sentinel-shield-cron', array( new CronPage( $this->c ), 'render' ) );
		add_submenu_page( self::SLUG, __( 'Tools & Testing', 'sentinel-shield' ), __( 'Tools & Testing', 'sentinel-shield' ), $cap, 'sentinel-shield-tools', array( new ToolsPage( $this->c ), 'render' ) );
	}

	/**
	 * Per-site override page on multisite.
	 */
	public function site_menu(): void {
		add_menu_page( __( 'Sentinel Shield', 'sentinel-shield' ), __( 'Sentinel Shield', 'sentinel-shield' ), 'manage_options', 'sentinel-shield-site', array( new SiteSettingsPage( $this->c ), 'render' ), 'dashicons-shield', 80 );
	}

	/**
	 * Admin assets on plugin pages only.
	 *
	 * @param string $hook Page hook.
	 */
	public function assets( string $hook ): void {
		if ( ! str_contains( $hook, 'sentinel-shield' ) ) {
			return;
		}
		wp_enqueue_style( 'sentinel-shield-admin', plugins_url( 'assets/admin.css', SENTINEL_SHIELD_FILE ), array(), SENTINEL_SHIELD_VERSION );
		wp_enqueue_script( 'sentinel-shield-admin', plugins_url( 'assets/admin.js', SENTINEL_SHIELD_FILE ), array(), SENTINEL_SHIELD_VERSION, true );
	}

	/**
	 * Settings link on the Plugins screen.
	 *
	 * @param array<int|string, string> $links Links.
	 * @return array<int|string, string>
	 */
	public function action_links( array $links ): array {
		array_unshift( $links, '<a href="' . esc_url( self::url( 'sentinel-shield-settings' ) ) . '">' . esc_html__( 'Settings', 'sentinel-shield' ) . '</a>' );
		return $links;
	}

	/**
	 * Flash messages, test mode banner, emergency notice and self-block warning.
	 */
	public function notices(): void {
		if ( ! current_user_can( self::cap() ) ) {
			return;
		}
		View::render_flash();
		$settings = $this->c->get( Settings::class );
		$screen   = get_current_screen();
		$ours     = $screen && str_contains( (string) $screen->id, 'sentinel-shield' );

		if ( SafetyGuard::emergency_disabled() ) {
			echo '<div class="notice notice-error"><p><strong>' . esc_html__( 'Sentinel Shield:', 'sentinel-shield' ) . '</strong> ' . esc_html__( 'SENTINEL_SHIELD_DISABLE is defined in wp-config.php, so all blocking is off. Remove it once you have regained access.', 'sentinel-shield' ) . '</p></div>';
		}

		// Onboarding only makes sense while still in test mode; once it is off the claims below are no longer true.
		if ( get_site_option( 'sentinel_shield_welcome' ) && $settings->is_enabled() && $settings->global_test_mode() ) {
			$dismiss     = wp_nonce_url( admin_url( 'admin-post.php?action=sentinel_shield_dismiss_welcome' ), 'sentinel_shield_dismiss_welcome' );
			$bin         = IpAddress::to_binary( (string) $this->c->get( 'client_ip' ) );
			$allowlisted = null !== $bin && $this->c->get( RuleCache::class )->get( 'allow' )->contains( $bin );
			echo '<div class="notice notice-info"><p><strong>' . esc_html__( 'Sentinel Shield is active in test mode.', 'sentinel-shield' ) . '</strong> '
				. esc_html__( 'Nothing is blocked yet.', 'sentinel-shield' ) . ' '
				. ( $allowlisted
					? esc_html__( 'Your IP has been allowlisted.', 'sentinel-shield' )
					: ( AdminProtection::is_real_client( (array) $this->c->get( 'client_ip_details' ) )
						? esc_html__( 'Your IP is not allowlisted yet; it will be the first time you save settings.', 'sentinel-shield' )
						: esc_html__( 'Your detected IP is a loopback or proxy address, so it will not be allowlisted. Configure IP Detection first.', 'sentinel-shield' ) ) ) . ' '
				. esc_html__( 'Next: confirm IP detection, review the Events log, then turn test mode off.', 'sentinel-shield' )
				. '</p><p><a class="button button-primary" href="' . esc_url( self::url( 'sentinel-shield-settings', array( 'tab' => 'ip_detection' ) ) ) . '">' . esc_html__( 'Check IP detection', 'sentinel-shield' ) . '</a> '
				. '<a class="button" href="' . esc_url( $dismiss ) . '">' . esc_html__( 'Dismiss', 'sentinel-shield' ) . '</a></p></div>';
		}

		if ( $settings->is_enabled() && $settings->global_test_mode() ) {
			$until = (int) $settings->get( 'general.test_mode_until', 0 );
			$when  = $until > 0
				/* translators: %s: date and time. */
				? sprintf( __( 'It ends automatically at %s.', 'sentinel-shield' ), wp_date( 'Y-m-d H:i', $until ) )
				: __( 'It stays on until you turn it off.', 'sentinel-shield' );
			echo '<div class="notice notice-warning ss-test-banner"><p><strong>' . esc_html__( 'Sentinel Shield test mode:', 'sentinel-shield' ) . '</strong> '
				. esc_html__( 'requests that would be blocked are only logged as "would block".', 'sentinel-shield' ) . ' ' . esc_html( $when )
				. ' <a href="' . esc_url( self::url( 'sentinel-shield-tools' ) ) . '">' . esc_html__( 'Manage test mode', 'sentinel-shield' ) . '</a></p></div>';
		}

		if ( $ours ) {
			$ip       = (string) $this->c->get( 'client_ip' );
			$decision = $this->c->get( AdminProtection::class )->self_check( $ip );
			if ( null !== $decision ) {
				echo '<div class="notice notice-warning"><p><strong>' . esc_html__( 'Your own IP matches a block rule.', 'sentinel-shield' ) . '</strong> ';
				printf(
					/* translators: 1: IP, 2: rule, 3: reason. */
					esc_html__( 'IP %1$s is covered by block rule %2$s (%3$s). Only the allowlist keeps you in. Remove the rule on the IP Rules page if this is not intended.', 'sentinel-shield' ),
					'<code>' . esc_html( $ip ) . '</code>',
					'<code>' . esc_html( (string) ( $decision->rule['label'] ?? '' ) ) . '</code>',
					esc_html( $decision->reason )
				);
				echo '</p></div>';
			}
		}
	}
}
