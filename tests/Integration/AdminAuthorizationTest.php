<?php
/**
 * Authorization matrix: every admin action, for every kind of account, with
 * every kind of bad nonce.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Tests\Integration;

use SentinelShield\Admin\Actions;
use SentinelShield\Admin\RulesPage;
use SentinelShield\Admin\TwoFactorPage;
use SentinelShield\Firewall\RuleCache;
use SentinelShield\Lockdown\Hardening;
use SentinelShield\Net\Cidr;
use SentinelShield\Plugin;
use SentinelShield\Repository\BlockRepository;
use SentinelShield\TwoFactor\UserTwoFactor;

/**
 * Thrown from the check_admin_referer hook once a request's nonce is accepted,
 * so a permitted request stops right there (some handlers stream a download
 * and exit).
 */
final class GuardPassed extends \RuntimeException {}

/**
 * Review 5 (P0): each admin operation is tried by an anonymous visitor, a
 * subscriber, an editor, an administrator and (on multisite) a site
 * administrator who is not a super admin, with a missing, malformed, expired,
 * wrong-action and other-user nonce, and with a valid one. Only the accounts
 * the operation is meant for, with a valid nonce, get past the checks; every
 * refused request leaves the plugin's options, tables, user meta and
 * scheduled events exactly as they were, and prints nothing.
 */
final class AdminAuthorizationTest extends \WP_UnitTestCase {

	use AdminUsers;

	/**
	 * Accounts by kind.
	 *
	 * @var array<string, int>
	 */
	private array $users = array();

	private Actions $actions;

	private TwoFactorPage $twofa;

	private int $rule_id = 0;

	public function set_up(): void {
		parent::set_up();
		$c = Plugin::instance()->container();
		global $wpdb;
		$wpdb->query( $wpdb->prepare( 'DELETE FROM %i', $c->get( BlockRepository::class )->table() ) );
		$c->get( RuleCache::class )->flush();
		$this->users = array(
			'anonymous'     => 0,
			'subscriber'    => (int) self::factory()->user->create( array( 'role' => 'subscriber' ) ),
			'editor'        => (int) self::factory()->user->create( array( 'role' => 'editor' ) ),
			'administrator' => self::create_admin(),
		);
		if ( is_multisite() ) {
			$this->users['site_admin'] = (int) self::factory()->user->create( array( 'role' => 'administrator' ) );
		}
		// Something for the delete, unblock and export handlers to act on.
		$this->rule_id = (int) $c->get( BlockRepository::class )->add( 'block', Cidr::parse( '203.0.113.88' ), 'matrix', 'manual' );
		update_site_option( 'sentinel_shield_welcome', 1 );
		wp_schedule_single_event( time() + 3600, 'sentinel_shield_matrix_probe', array( 'x' ) );
		$this->actions = new Actions( $c );
		$this->actions->register();
		$this->twofa = new TwoFactorPage( $c );
		$this->twofa->register();
		add_action( 'check_admin_referer', array( self::class, 'stop_when_accepted' ), 10, 2 );
		add_filter( 'wp_redirect', array( self::class, 'stop_on_redirect' ) );
		add_filter( 'pre_http_request', array( self::class, 'no_network' ) );
	}

	public function tear_down(): void {
		remove_action( 'check_admin_referer', array( self::class, 'stop_when_accepted' ), 10 );
		remove_filter( 'wp_redirect', array( self::class, 'stop_on_redirect' ) );
		remove_filter( 'pre_http_request', array( self::class, 'no_network' ) );
		foreach ( array( 'save_settings', 'save_site_settings', 'add_rule', 'delete_rule', 'unblock_ip', 'export_rules', 'import_rules', 'export_settings', 'import_settings', 'tool', 'preview_block', 'dismiss_welcome', 'feeds_update', 'cron_control', 'lockdown', 'geo', 'login_security', 'server', 'alerts' ) as $action ) {
			remove_all_actions( 'admin_post_sentinel_shield_' . $action );
		}
		remove_all_actions( 'admin_post_' . TwoFactorPage::ACTION );
		wp_clear_scheduled_hook( 'sentinel_shield_matrix_probe', array( 'x' ) );
		$_POST    = array();
		$_GET     = array();
		$_REQUEST = array();
		$_FILES   = array();
		wp_set_current_user( 0 );
		parent::tear_down();
	}

	/**
	 * Hook: a valid nonce ends the request before the handler does anything.
	 *
	 * @param string    $action Nonce action.
	 * @param int|false $result Verification result.
	 * @throws GuardPassed When the nonce was accepted.
	 */
	public static function stop_when_accepted( $action, $result ): void {
		if ( $result ) {
			throw new GuardPassed( (string) $action );
		}
	}

	/**
	 * Filter: a redirect ends the request (handlers exit after redirecting).
	 *
	 * @param string $location Target.
	 * @throws RedirectedTo Always.
	 */
	public static function stop_on_redirect( $location ): string {
		throw new RedirectedTo( (string) $location );
	}

	/**
	 * Filter: no handler reaches the network in these tests.
	 */
	public static function no_network(): \WP_Error {
		return new \WP_Error( 'blocked', 'No network in tests.' );
	}

	/**
	 * Every handler with a request that would change something if it ran.
	 *
	 * @return array<string, array{nonce:string, cap:string, post?:array<string, mixed>, get?:array<string, mixed>}>
	 */
	private function operations(): array {
		$settings = array( 'general' => array( 'test_mode' => '1' ) );
		return array(
			'save_settings'      => array( 'post' => array( 'tab' => 'general', 'sentinel_shield' => $settings ) ),
			'save_site_settings' => array(
				'cap'  => 'manage_options',
				'post' => array(
					'sentinel_override' => array( 'general.test_mode' ),
					'sentinel_shield'   => $settings,
				),
			),
			'add_rule'           => array( 'post' => array( 'value' => '198.51.100.99', 'list_type' => 'block', 'reason' => 'matrix' ) ),
			'delete_rule'        => array( 'get' => array( 'id' => $this->rule_id ) ),
			'unblock_ip'         => array( 'post' => array( 'ip' => '203.0.113.88' ) ),
			'export_rules'       => array(),
			'import_rules'       => array(),
			'export_settings'    => array(),
			'import_settings'    => array( 'post' => array( 'sentinel_json_text' => (string) wp_json_encode( array( 'plugin' => 'sentinel-shield', 'settings' => $settings ) ) ) ),
			'tool'               => array( 'post' => array( 'tool' => 'test_mode', 'mode' => 'on' ) ),
			'preview_block'      => array(),
			'dismiss_welcome'    => array(),
			'feeds_update'       => array( 'post' => array( 'feed' => 'spamhaus_drop' ) ),
			'cron_control'       => array(
				'post' => array(
					'op'        => 'delete',
					'hook'      => 'sentinel_shield_matrix_probe',
					'timestamp' => (string) wp_next_scheduled( 'sentinel_shield_matrix_probe', array( 'x' ) ),
					'sig'       => md5( serialize( array( 'x' ) ) ), // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.serialize_serialize -- WP-Cron's own key.
				),
			),
			'lockdown'           => array( 'post' => array( 'op' => 'logout_all' ) ),
			'geo'                => array( 'post' => array( 'op' => 'test', 'ip' => '198.51.100.7' ) ),
			'login_security'     => array( 'post' => array( 'op' => 'reset_twofa', 'user_id' => $this->users['administrator'] ) ),
			'server'             => array( 'post' => array( 'op' => 'cf_token', 'token' => 'attacker-token' ) ),
			'alerts'             => array( 'post' => array( 'op' => 'new_secret' ) ),
		);
	}

	/**
	 * A nonce of the given kind for the current user.
	 *
	 * @param string $kind   valid, missing, malformed, expired, other_action or other_user.
	 * @param string $action Nonce action.
	 */
	private function nonce( string $kind, string $action ): ?string {
		switch ( $kind ) {
			case 'missing':
				return null;
			case 'malformed':
				return 'not-a-nonce';
			case 'expired':
				// What wp_create_nonce() returned a day and more ago (two ticks back).
				$tick = wp_nonce_tick( $action ) - 2;
				return substr( wp_hash( $tick . '|' . $action . '|' . get_current_user_id() . '|' . wp_get_session_token(), 'nonce' ), -12, 10 );
			case 'other_action':
				return wp_create_nonce( 'sentinel_shield_dismiss_welcome' === $action ? 'sentinel_shield_add_rule' : 'sentinel_shield_dismiss_welcome' );
			case 'other_user':
				$me = get_current_user_id();
				wp_set_current_user( $this->users['administrator'] === $me ? $this->users['editor'] : $this->users['administrator'] );
				$nonce = wp_create_nonce( $action );
				wp_set_current_user( $me );
				return $nonce;
			default:
				return wp_create_nonce( $action );
		}
	}

	/**
	 * Everything an admin action could change: the plugin's options (site and
	 * network), its tables, its user meta, login sessions and scheduled events.
	 */
	private static function snapshot(): string {
		global $wpdb;
		$state = array(
			$wpdb->get_results( $wpdb->prepare( 'SELECT option_name, option_value FROM %i WHERE option_name LIKE %s OR option_name LIKE %s OR option_name = %s ORDER BY option_name', $wpdb->options, '%sentinel%', '%_transient_%', 'cron' ), ARRAY_N ),
			$wpdb->get_results( $wpdb->prepare( 'SELECT user_id, meta_key, meta_value FROM %i WHERE meta_key LIKE %s OR meta_key = %s ORDER BY umeta_id', $wpdb->usermeta, '%sentinel%', 'session_tokens' ), ARRAY_N ),
		);
		if ( is_multisite() ) {
			$state[] = $wpdb->get_results( $wpdb->prepare( 'SELECT meta_key, meta_value FROM %i WHERE meta_key LIKE %s ORDER BY meta_id', $wpdb->sitemeta, '%sentinel%' ), ARRAY_N );
		}
		foreach ( (array) $wpdb->get_col( $wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( $wpdb->base_prefix . 'sentinel' ) . '%' ) ) as $table ) {
			$state[ $table ] = $wpdb->get_results( $wpdb->prepare( 'SELECT * FROM %i', $table ), ARRAY_N );
		}
		return md5( serialize( $state ) ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.serialize_serialize -- Comparison only.
	}

	/**
	 * Sends one request to an admin-post action.
	 *
	 * @param string               $hook  admin_post hook suffix.
	 * @param string|null          $nonce Nonce, or null for none.
	 * @param array<string, mixed> $post  POST fields.
	 * @param array<string, mixed> $get   GET fields.
	 * @return array{0:string, 1:string} Outcome (passed, refused, redirect or done) and output.
	 */
	private static function send( string $hook, ?string $nonce, array $post = array(), array $get = array() ): array {
		$_POST = $post;
		$_GET  = $get;
		if ( null !== $nonce ) {
			$_POST['_wpnonce'] = $nonce;
		}
		$_REQUEST = array_merge( $_GET, $_POST );
		ob_start();
		try {
			do_action( 'admin_post_' . $hook );
			$outcome = 'done';
		} catch ( GuardPassed $e ) {
			$outcome = 'passed';
		} catch ( \WPDieException $e ) {
			$outcome = 'refused';
		} catch ( RedirectedTo $e ) {
			$outcome = 'redirect';
		} finally {
			$output   = (string) ob_get_clean();
			$_POST    = array();
			$_GET     = array();
			$_REQUEST = array();
		}
		return array( $outcome, $output );
	}

	/**
	 * Whether an account kind may perform an operation needing $cap.
	 *
	 * @param string $kind Account kind.
	 * @param string $cap  Capability the operation needs ('' = the plugin's).
	 */
	private static function allowed( string $kind, string $cap ): bool {
		if ( 'administrator' === $kind ) {
			return true; // A super admin on multisite.
		}
		return 'site_admin' === $kind && 'manage_options' === $cap;
	}

	public function test_no_admin_action_is_open_to_visitors_who_are_not_logged_in(): void {
		global $wp_filter;
		$open = array_filter( array_keys( $wp_filter ), static fn( $hook ): bool => is_string( $hook ) && str_starts_with( $hook, 'admin_post_nopriv_sentinel' ) );
		$this->assertSame( array(), array_values( $open ) );
		$this->assertTrue( has_action( 'admin_post_sentinel_shield_add_rule' ) > 0, 'handlers are registered' );
	}

	public function test_every_admin_action_refuses_the_wrong_account_or_nonce_without_changing_anything(): void {
		$kinds   = array( 'missing', 'malformed', 'expired', 'other_action', 'other_user', 'valid' );
		$checked = 0;
		foreach ( $this->operations() as $action => $op ) {
			$hook = 'sentinel_shield_' . $action;
			$cap  = (string) ( $op['cap'] ?? '' );
			foreach ( $this->users as $who => $user_id ) {
				wp_set_current_user( $user_id );
				foreach ( $kinds as $kind ) {
					$before            = self::snapshot();
					[ $outcome, $out ] = self::send( $hook, $this->nonce( $kind, $hook ), $op['post'] ?? array(), $op['get'] ?? array() );
					$label             = "$action as $who with a $kind nonce";
					if ( 'valid' === $kind && self::allowed( $who, $cap ) ) {
						$this->assertSame( 'passed', $outcome, "$label: should get past the checks" );
					} else {
						$this->assertSame( 'refused', $outcome, "$label: should be refused" );
						$this->assertSame( $before, self::snapshot(), "$label: changed data" );
						$this->assertStringNotContainsString( '203.0.113.88', $out, "$label: leaked rules" );
					}
					++$checked;
				}
			}
		}
		$this->assertSame( count( $this->operations() ) * count( $this->users ) * count( $kinds ), $checked );
	}

	/**
	 * The checks are not vacuous: the same requests, allowed through, do change
	 * things (the handler runs to its redirect).
	 */
	public function test_the_permitted_requests_do_take_effect(): void {
		remove_action( 'check_admin_referer', array( self::class, 'stop_when_accepted' ), 10 );
		wp_set_current_user( $this->users['administrator'] );
		$c = Plugin::instance()->container();
		foreach ( array( 'add_rule', 'delete_rule', 'dismiss_welcome', 'cron_control' ) as $action ) {
			$op                = $this->operations()[ $action ];
			$before            = self::snapshot();
			[ $outcome ]       = self::send( 'sentinel_shield_' . $action, $this->nonce( 'valid', 'sentinel_shield_' . $action ), $op['post'] ?? array(), $op['get'] ?? array() );
			$this->assertSame( 'redirect', $outcome, $action );
			$this->assertNotSame( $before, self::snapshot(), "$action changed nothing" );
		}
		$this->assertNotNull( $c->get( BlockRepository::class )->find_exact( 'block', Cidr::parse( '198.51.100.99' ) ) );
		$this->assertNull( $c->get( BlockRepository::class )->find_exact( 'block', Cidr::parse( '203.0.113.88' ) ) );
		$this->assertFalse( get_site_option( 'sentinel_shield_welcome' ) );
		$this->assertFalse( wp_next_scheduled( 'sentinel_shield_matrix_probe', array( 'x' ) ) );
	}

	/**
	 * The two-factor page acts only on the logged-in user's own account, with a
	 * valid nonce; a visitor who is not logged in is refused.
	 */
	public function test_the_two_factor_page_needs_a_login_and_a_valid_nonce(): void {
		foreach ( $this->users as $who => $user_id ) {
			wp_set_current_user( $user_id );
			foreach ( array( 'missing', 'malformed', 'expired', 'other_action', 'other_user', 'valid' ) as $kind ) {
				$before      = self::snapshot();
				[ $outcome ] = self::send( TwoFactorPage::ACTION, $this->nonce( $kind, TwoFactorPage::ACTION ), array( 'op' => 'backup_new' ) );
				if ( 'valid' === $kind && 0 !== $user_id ) {
					$this->assertSame( 'passed', $outcome, "$who with a valid nonce" );
				} else {
					$this->assertSame( 'refused', $outcome, "$who with a $kind nonce" );
					$this->assertSame( $before, self::snapshot(), "$who with a $kind nonce changed data" );
				}
			}
		}
	}

	/**
	 * Resetting someone else's two-factor from their profile needs the right
	 * to edit that user and the resetting user's own password.
	 */
	public function test_profile_two_factor_reset_needs_edit_rights_and_the_password(): void {
		$users  = Plugin::instance()->container()->get( UserTwoFactor::class );
		$target = (int) self::factory()->user->create( array( 'role' => 'author' ) );
		$users->new_backup_codes( $target );
		$reset = function ( int $as, string $password ) use ( $target, $users ): bool {
			wp_set_password( 'right-pass', $as );
			clean_user_cache( $as );
			wp_set_current_user( 0 );
			wp_set_current_user( $as );
			$_POST = array(
				'sentinel_shield_2fa_reset'          => '1',
				'sentinel_shield_2fa_reset_password' => $password,
			);
			try {
				$this->twofa->profile_reset( $target );
			} finally {
				$_POST = array();
			}
			return 0 === $users->backup_remaining( $target );
		};
		$this->assertFalse( $reset( $this->users['subscriber'], 'right-pass' ), 'a subscriber cannot reset another account' );
		$this->assertFalse( $reset( $this->users['administrator'], 'wrong-pass' ), 'the password is checked' );
		$this->assertTrue( $reset( $this->users['administrator'], 'right-pass' ) );
	}

	/**
	 * The rules screen's bulk delete (a GET with the list table's nonce).
	 */
	public function test_bulk_rule_delete_checks_the_account_and_nonce(): void {
		$page = new RulesPage( Plugin::instance()->container() );
		foreach ( $this->users as $who => $user_id ) {
			wp_set_current_user( $user_id );
			foreach ( array( 'missing', 'expired', 'other_user', 'valid' ) as $kind ) {
				$_GET = array(
					'action' => 'delete',
					'rule'   => array( $this->rule_id ),
				);
				$nonce = $this->nonce( $kind, 'bulk-sentinel_rules' );
				if ( null !== $nonce ) {
					$_GET['_wpnonce'] = $nonce;
				}
				$_REQUEST = $_GET;
				$before   = self::snapshot();
				try {
					$page->load();
					$outcome = 'done';
				} catch ( GuardPassed $e ) {
					$outcome = 'passed';
				} catch ( \WPDieException $e ) {
					$outcome = 'refused';
				} finally {
					$_GET     = array();
					$_REQUEST = array();
				}
				if ( 'valid' === $kind && self::allowed( $who, '' ) ) {
					$this->assertSame( 'passed', $outcome, "$who: bulk delete" );
				} else {
					$this->assertSame( 'refused', $outcome, "$who with a $kind nonce: bulk delete" );
					$this->assertSame( $before, self::snapshot() );
				}
			}
		}
	}

	/**
	 * Deactivating or deleting the plugin from a request needs an account that
	 * may activate plugins and one of the Plugins screen's own nonces.
	 */
	public function test_plugin_changes_need_a_plugins_screen_nonce(): void {
		$hardening = Plugin::instance()->container()->get( Hardening::class );
		$base      = plugin_basename( SENTINEL_SHIELD_FILE );
		foreach ( $this->users as $who => $user_id ) {
			wp_set_current_user( $user_id );
			foreach ( array( 'missing', 'malformed', 'expired', 'valid' ) as $kind ) {
				$nonce    = $this->nonce( $kind, 'deactivate-plugin_' . $base );
				$_REQUEST = null === $nonce ? array() : array( '_wpnonce' => $nonce );
				$allowed  = $hardening->change_allowed();
				$_REQUEST = array();
				$this->assertSame( 'valid' === $kind && user_can( $user_id, 'activate_plugins' ), $allowed, "$who with a $kind nonce" );
			}
		}
	}
}
