<?php
/**
 * Handlers for admin-post.php. Every handler checks capability and nonce first.
 *
 * phpcs:disable WordPress.Security.NonceVerification -- Each handler calls View::guard()
 * (current_user_can() + check_admin_referer()) before reading input; WPCS can't see
 * verification done in a static helper.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Admin;

use SentinelShield\Container;
use SentinelShield\Cron\CronControl;
use SentinelShield\Feeds\FeedCatalog;
use SentinelShield\Feeds\FeedParser;
use SentinelShield\Feeds\FeedUpdater;
use SentinelShield\Firewall\BlockPage;
use SentinelShield\Firewall\Decision;
use SentinelShield\Firewall\Gate;
use SentinelShield\Firewall\RuleCache;
use SentinelShield\Geo\GeoResolver;
use SentinelShield\Geo\GeoUpdater;
use SentinelShield\Geo\LoginGeoGuard;
use SentinelShield\Lockdown\AdminRegistry;
use SentinelShield\Lockdown\FileIntegrity;
use SentinelShield\Lockdown\IntegrityScanner;
use SentinelShield\Lockout\Unblocker;
use SentinelShield\Repository\LoginAttemptRepository;
use SentinelShield\Modules\GeoLoginModule;
use SentinelShield\Modules\LockdownModule;
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
use SentinelShield\TwoFactor\UserTwoFactor;
use SentinelShield\Unlock\UnlockService;
use SentinelShield\Firewall\EarlyGate;
use SentinelShield\Firewall\CloudflareSync;
use SentinelShield\Audit\AuditExporter;

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
			'feeds_update'       => 'feeds_update',
			'cron_control'       => 'cron_control',
			'lockdown'           => 'lockdown',
			'geo'                => 'geo',
			'login_security'     => 'login_security',
			'server'             => 'server',
			'alerts'             => 'alerts',
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
	 * Refuses to switch email codes off while two-factor authentication is
	 * required for the current user and they have no authenticator app: their
	 * next login would be impossible.
	 *
	 * @param array<string, mixed> $settings Settings about to be saved.
	 * @return array<string, mixed>
	 */
	private function keep_own_twofa_login( array $settings ): array {
		$required = (string) Settings::get_path( $settings, 'twofa.required', 'none' );
		$user     = wp_get_current_user();
		if ( Settings::get_path( $settings, 'twofa.email', true ) || 'none' === $required || ! $user->exists() ) {
			return $settings;
		}
		if ( 'privileged' === $required && ! AdminRegistry::is_privileged( $user ) ) {
			return $settings;
		}
		if ( null !== $this->c->get( UserTwoFactor::class )->totp_secret( (int) $user->ID ) ) {
			return $settings;
		}
		Settings::set_path( $settings, 'twofa.email', true );
		View::flash( 'error', __( 'Email codes were kept on: two-factor authentication is required for your account and you have no authenticator app, so you could not log in again. Set up an app under Users → Two-Factor Authentication first.', 'sentinel-shield' ) );
		return $settings;
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
		if ( ! AdminProtection::is_real_client( (array) $this->c->get( 'client_ip_details' ) ) ) {
			/* translators: %s: IP address. */
			View::flash( 'warning', sprintf( __( 'Your detected IP %s is a loopback or proxy address, so it was not allowlisted (that would exempt every visitor). Check Settings → IP Detection.', 'sentinel-shield' ), $ip ) );
		} else {
			$days = (int) $this->c->get( Settings::class )->get( 'unlock.admin_allow_days', 30 );
			if ( $protection->ensure_allowlisted( $ip, get_current_user_id(), $days ) ) {
				View::flash(
					'info',
					$days > 0
						/* translators: 1: IP address, 2: days. */
						? sprintf( __( 'Your IP %1$s was allowlisted so you cannot lock yourself out. The entry lasts %2$d days and renews while you use the dashboard from this IP.', 'sentinel-shield' ), $ip, $days )
						/* translators: %s: IP address. */
						: sprintf( __( 'Your IP %s was added to the permanent allowlist so you cannot lock yourself out.', 'sentinel-shield' ), $ip )
				);
			}
		}
		$decision = $protection->self_check( $ip );
		if ( null !== $decision ) {
			/* translators: 1: IP address, 2: rule. */
			View::flash( 'warning', sprintf( __( 'Warning: your IP %1$s matches block rule %2$s. You are only allowed in because of the allowlist.', 'sentinel-shield' ), $ip, (string) ( $decision->rule['label'] ?? '' ) ) );
		}
		GeoLoginModule::protect_current_admin( $this->c );
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
	 * Run now, pause, resume, reschedule or delete one scheduled task.
	 */
	public function cron_control(): void {
		View::guard( 'sentinel_shield_cron_control' );
		$op       = isset( $_POST['op'] ) ? sanitize_key( wp_unslash( $_POST['op'] ) ) : '';
		$switched = is_multisite() && get_current_blog_id() !== get_main_site_id();
		if ( $switched ) {
			switch_to_blog( get_main_site_id() );
		}
		[ $type, $message, $hook ] = $this->cron_op( $op );
		if ( $switched ) {
			restore_current_blog();
		}
		if ( 'success' === $type ) {
			$this->audit(
				'cron_' . $op,
				array( 'hook' => $hook )
			);
		}
		View::flash( $type, $message );
		View::redirect( Admin::url( 'sentinel-shield-cron' ) );
	}

	/**
	 * Malware lockdown page buttons: scan, approve findings and administrators, log out everyone.
	 */
	public function lockdown(): void {
		View::guard( 'sentinel_shield_lockdown' );
		$op       = isset( $_POST['op'] ) ? sanitize_key( wp_unslash( $_POST['op'] ) ) : '';
		$registry = $this->c->get( AdminRegistry::class );
		$back     = Admin::url( 'sentinel-shield-lockdown' );
		switch ( $op ) {
			case 'scan':
				$report = $this->c->get( IntegrityScanner::class )->run();
				LockdownModule::after_scan( $this->c, $report, false );
				$alerts = count( array_filter( $report['findings'], array( IntegrityScanner::class, 'is_alert' ) ) );
				$this->audit( 'lockdown_scan' );
				View::flash(
					$alerts ? 'warning' : 'success',
					$alerts
						/* translators: %d: count. */
						? sprintf( _n( 'Scan finished: %d item needs attention.', 'Scan finished: %d items need attention.', $alerts, 'sentinel-shield' ), $alerts )
						: __( 'Scan finished: no critical findings or warnings.', 'sentinel-shield' )
				);
				if ( empty( $report['complete'] ) ) {
					View::flash( 'info', __( 'The uploads folder holds more files than one run checks; the rest are checked in the background over the next minutes, and this page shows the progress.', 'sentinel-shield' ) );
				}
				$back .= '#ss-scan';
				break;
			case 'integrity':
				$this->c->get( FileIntegrity::class )->start( true );
				$result = LockdownModule::integrity_step( $this->c, 10.0, false );
				$this->audit( 'integrity_check' );
				if ( $result['done'] ) {
					$alerts = count( array_filter( (array) ( $result['report']['findings'] ?? array() ), array( IntegrityScanner::class, 'is_alert' ) ) );
					View::flash(
						$alerts ? 'warning' : 'success',
						$alerts
							/* translators: %d: count. */
							? sprintf( _n( 'File check finished: %d file needs attention.', 'File check finished: %d files need attention.', $alerts, 'sentinel-shield' ), $alerts )
							: __( 'File check finished: everything that could be verified matches WordPress.org.', 'sentinel-shield' )
					);
				} else {
					/* translators: 1: targets done, 2: total. */
					View::flash( 'info', sprintf( __( 'File check started: %1$d of %2$d items done. It continues in the background; reload this page to see the progress.', 'sentinel-shield' ), $result['progress']['done'], $result['progress']['total'] ) );
				}
				$back .= '#ss-integrity';
				break;
			case 'approve':
			case 'unapprove':
				$id = isset( $_POST['id'] ) ? sanitize_key( wp_unslash( $_POST['id'] ) ) : '';
				if ( 'approve' === $op ) {
					$finding = IntegrityScanner::approve( $id, get_current_user_id() );
					if ( null === $finding ) {
						View::flash( 'error', __( 'That item is no longer in the scan results. Run the scan again.', 'sentinel-shield' ) );
						break;
					}
					$this->audit( 'lockdown_approve', array( 'title' => $finding['title'] ) );
					/* translators: %s: finding title. */
					View::flash( 'success', sprintf( __( 'Approved: %s', 'sentinel-shield' ), $finding['title'] ) );
				} elseif ( IntegrityScanner::unapprove( $id ) ) {
					$this->audit( 'lockdown_unapprove', array( 'id' => $id ) );
					View::flash( 'success', __( 'Approval withdrawn.', 'sentinel-shield' ) );
				}
				$back .= '#ss-scan';
				break;
			case 'approve_admin':
			case 'revoke_admin':
				$user_id = isset( $_POST['user_id'] ) ? absint( $_POST['user_id'] ) : 0;
				$user    = get_userdata( $user_id );
				if ( $registry->is_fixed() ) {
					View::flash( 'error', __( 'The administrator list is fixed in wp-config.php (SENTINEL_SHIELD_ADMINS). Change it there.', 'sentinel-shield' ) );
				} elseif ( ! $user instanceof \WP_User || ! AdminRegistry::is_privileged( $user ) ) {
					View::flash( 'error', __( 'That account is not an administrator.', 'sentinel-shield' ) );
				} elseif ( 'approve_admin' === $op ) {
					$registry->approve( $user_id, get_current_user_id() );
					$this->audit( 'lockdown_approve_admin', array( 'user' => $user->user_login ) );
					/* translators: %s: login. */
					View::flash( 'success', sprintf( __( 'Approved administrator %s.', 'sentinel-shield' ), $user->user_login ) );
				} elseif ( get_current_user_id() === $user_id ) {
					View::flash( 'error', __( 'You cannot withdraw your own approval.', 'sentinel-shield' ) );
				} else {
					$registry->revoke( $user_id );
					$this->audit( 'lockdown_revoke_admin', array( 'user' => $user->user_login ) );
					/* translators: %s: login. */
					View::flash( 'success', sprintf( __( 'Withdrew approval for %s.', 'sentinel-shield' ), $user->user_login ) );
				}
				$back .= '#ss-admins';
				break;
			case 'logout_all':
				$this->audit( 'lockdown_logout_all' );
				\WP_Session_Tokens::destroy_all_for_all_users();
				$back = wp_login_url( $back );
				break;
			default:
				View::flash( 'error', __( 'Unknown action.', 'sentinel-shield' ) );
		}
		View::redirect( $back );
	}

	/**
	 * Performs one cron action on the current site.
	 *
	 * @param string $op Operation.
	 * @return array{0:string, 1:string, 2:string} Flash type, message, hook.
	 */
	private function cron_op( string $op ): array {
		if ( in_array( $op, array( 'resume', 'forget' ), true ) ) {
			$key    = isset( $_POST['key'] ) ? substr( (string) wp_unslash( $_POST['key'] ), 0, 300 ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Only used as an exact array key.
			$paused = CronControl::paused();
			$hook   = (string) ( $paused[ $key ]['hook'] ?? '' );
			if ( 'forget' === $op ) {
				return CronControl::forget( $key )
					/* translators: %s: hook name. */
					? array( 'success', sprintf( __( 'Deleted paused task %s.', 'sentinel-shield' ), $hook ), $hook )
					: array( 'error', __( 'That task is not paused.', 'sentinel-shield' ), $hook );
			}
			$result = CronControl::resume( $key );
			return is_wp_error( $result )
				? array( 'error', $result->get_error_message(), $hook )
				/* translators: %s: hook name. */
				: array( 'success', sprintf( __( 'Resumed %s.', 'sentinel-shield' ), $hook ), $hook );
		}

		$timestamp = isset( $_POST['timestamp'] ) ? absint( $_POST['timestamp'] ) : 0;
		$hook      = isset( $_POST['hook'] ) ? substr( (string) wp_unslash( $_POST['hook'] ), 0, 300 ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Only used for an exact lookup of an existing event.
		$sig       = isset( $_POST['sig'] ) ? sanitize_key( wp_unslash( $_POST['sig'] ) ) : '';
		$event     = 1 === preg_match( '/^[a-f0-9]{32}$/', $sig ) ? CronControl::find( $timestamp, $hook, $sig ) : null;
		if ( null === $event ) {
			return array( 'error', __( 'That task has already run or changed since the page loaded. Check the list again.', 'sentinel-shield' ), $hook );
		}
		switch ( $op ) {
			case 'run':
				$result = CronControl::run_now( $event );
				/* translators: %s: hook name. */
				$done = sprintf( __( '%s was queued to run now. Reload in a few seconds to see the result under "Last run".', 'sentinel-shield' ), $hook );
				break;
			case 'pause':
				$result = CronControl::pause( $event, get_current_user_id() );
				/* translators: %s: hook name. */
				$done = sprintf( __( 'Paused %s. Its plugin cannot schedule it again until you resume it.', 'sentinel-shield' ), $hook );
				break;
			case 'delete':
				$result = CronControl::delete( $event );
				/* translators: %s: hook name. */
				$done = sprintf( __( 'Deleted %s. If its plugin is still active it may schedule it again; use Pause to stop it for good.', 'sentinel-shield' ), $hook );
				break;
			case 'reschedule':
				$schedule = isset( $_POST['schedule'] ) ? sanitize_key( wp_unslash( $_POST['schedule'] ) ) : '';
				$schedule = 'once' === $schedule ? '' : $schedule;
				$next_raw = isset( $_POST['next_run'] ) ? sanitize_text_field( wp_unslash( $_POST['next_run'] ) ) : '';
				$next     = (int) $event['timestamp'];
				if ( '' !== $next_raw ) {
					$parsed = \DateTimeImmutable::createFromFormat( 'Y-m-d\TH:i', $next_raw, wp_timezone() );
					if ( false === $parsed ) {
						return array( 'error', __( 'Invalid date and time.', 'sentinel-shield' ), $hook );
					}
					$next = $parsed->getTimestamp();
				}
				$result = CronControl::reschedule( $event, $schedule, $next );
				/* translators: 1: hook name, 2: date and time. */
				$done = sprintf( __( 'Rescheduled %1$s; next run %2$s.', 'sentinel-shield' ), $hook, wp_date( 'Y-m-d H:i', $next ) );
				break;
			default:
				return array( 'error', __( 'Unknown action.', 'sentinel-shield' ), $hook );
		}
		return is_wp_error( $result ) ? array( 'error', $result->get_error_message(), $hook ) : array( 'success', $done, $hook );
	}

	/**
	 * Downloads one blocklist feed, or all enabled ones, now.
	 */
	public function feeds_update(): void {
		View::guard( 'sentinel_shield_feeds_update' );
		$back    = Admin::url( 'sentinel-shield-settings', array( 'tab' => 'blocklists' ) );
		$feed    = isset( $_POST['feed'] ) ? sanitize_key( wp_unslash( $_POST['feed'] ) ) : '';
		$updater = $this->c->get( FeedUpdater::class );
		$slugs   = 'all' === $feed ? $updater->enabled() : array_intersect( array( $feed ), $updater->enabled() );
		if ( ! $slugs ) {
			View::flash( 'error', __( 'That list is not enabled.', 'sentinel-shield' ) );
			View::redirect( $back );
		}
		$state = array();
		foreach ( $slugs as $slug ) {
			$result = $updater->update( $slug );
			$name   = FeedCatalog::NAMES[ $slug ] ?? $slug;
			if ( is_wp_error( $result ) ) {
				View::flash( 'error', $result->get_error_message() );
				continue;
			}
			$state = $updater->state();
			/* translators: 1: list name, 2: number of ranges. */
			View::flash( 'success', sprintf( __( '%1$s is up to date: %2$s ranges.', 'sentinel-shield' ), $name, number_format_i18n( (int) ( $state[ $slug ]['count'] ?? 0 ) ) ) );
		}
		$this->audit( 'feeds_updated', array( 'feeds' => array_values( $slugs ) ) );
		View::redirect( $back );
	}

	/**
	 * Login location tools: database update and IP lookup.
	 */
	public function geo(): void {
		View::guard( 'sentinel_shield_geo' );
		$op   = isset( $_POST['op'] ) ? sanitize_key( wp_unslash( $_POST['op'] ) ) : '';
		$back = Admin::url( 'sentinel-shield-settings', array( 'tab' => 'geo' ) );
		if ( 'update' === $op ) {
			$result = $this->c->get( GeoUpdater::class )->update( true );
			if ( is_wp_error( $result ) ) {
				View::flash( 'error', $result->get_error_message() );
			} else {
				/* translators: 1: edition month, 2: number of ranges. */
				View::flash( 'success', sprintf( __( 'Country database %1$s installed: %2$s ranges.', 'sentinel-shield' ), (string) ( $result['month'] ?? '' ), number_format_i18n( (int) ( $result['v4'] ?? 0 ) + (int) ( $result['v6'] ?? 0 ) ) ) );
			}
			$this->audit( 'geo_db_update' );
		} elseif ( 'lookup' === $op ) {
			$ip    = isset( $_POST['ip'] ) ? trim( sanitize_text_field( wp_unslash( $_POST['ip'] ) ) ) : '';
			$name  = isset( $_POST['user'] ) ? sanitize_user( wp_unslash( $_POST['user'] ) ) : '';
			$user  = '' === $name ? null : LoginGeoGuard::find_account( $name );
			$check = $this->c->get( LoginGeoGuard::class )->check( $ip, $user );
			if ( '' === $check['source'] ) {
				// Not checked (off, out of scope or allowlisted): still show the country.
				$check = array_merge( $check, $this->c->get( GeoResolver::class )->resolve( $ip ) );
			}
			View::put_result(
				'geo_lookup',
				array(
					'ip'      => $ip,
					'user'    => $name,
					'country' => $check['country'],
					'source'  => $check['source'],
					'allowed' => $check['allowed'],
					'explain' => LoginGeoGuard::explain( $check ),
				)
			);
		} else {
			View::flash( 'error', __( 'Unknown action.', 'sentinel-shield' ) );
		}
		View::redirect( $back );
	}

	/**
	 * Alerts & Audit Log tab actions: test every channel, send now, new secret.
	 */
	public function alerts(): void {
		View::guard( 'sentinel_shield_alerts' );
		$op     = isset( $_POST['op'] ) ? sanitize_key( wp_unslash( $_POST['op'] ) ) : '';
		$export = $this->c->get( AuditExporter::class );
		$back   = Admin::url( 'sentinel-shield-settings', array( 'tab' => 'alerts' ) );
		switch ( $op ) {
			case 'test':
				$names = array(
					'email'     => __( 'Email', 'sentinel-shield' ),
					'webhook'   => __( 'Webhook', 'sentinel-shield' ),
					'heartbeat' => __( 'Heartbeat', 'sentinel-shield' ),
					'syslog'    => __( 'Syslog', 'sentinel-shield' ),
				);
				foreach ( $export->test() as $channel => $result ) {
					View::flash( 'info', ( $names[ $channel ] ?? $channel ) . ': ' . $result );
				}
				$this->audit( 'alert_test' );
				$back .= '#ss-delivery';
				break;
			case 'send':
				$state = $export->run();
				View::flash( empty( $state['failures'] ) ? 'success' : 'error', empty( $state['failures'] ) ? __( 'Waiting events sent.', 'sentinel-shield' ) : (string) $state['error'] );
				$back .= '#ss-audit';
				break;
			case 'new_secret':
				AuditExporter::new_secret();
				$this->audit( 'audit_secret_renewed' );
				View::flash( 'success', __( 'A new signing secret was created. Update your receiver.', 'sentinel-shield' ) );
				$back .= '#ss-audit';
				break;
			default:
				View::flash( 'error', __( 'Unknown action.', 'sentinel-shield' ) );
		}
		View::redirect( $back );
	}

	/**
	 * Server & CDN tab actions: rebuild the snapshot, Cloudflare token, test and sync.
	 */
	public function server(): void {
		View::guard( 'sentinel_shield_server' );
		$op         = isset( $_POST['op'] ) ? sanitize_key( wp_unslash( $_POST['op'] ) ) : '';
		$cloudflare = $this->c->get( CloudflareSync::class );
		$back       = Admin::url( 'sentinel-shield-settings', array( 'tab' => 'server' ) );
		switch ( $op ) {
			case 'rebuild':
				$state = $this->c->get( EarlyGate::class )->rebuild();
				$this->audit( 'early_gate_rebuild' );
				View::flash( empty( $state['error'] ) ? 'success' : 'error', empty( $state['error'] ) ? __( 'Snapshot rebuilt.', 'sentinel-shield' ) : (string) $state['error'] );
				$back .= '#ss-early';
				break;
			case 'cf_token':
				$token = isset( $_POST['token'] ) ? sanitize_text_field( wp_unslash( $_POST['token'] ) ) : '';
				$cloudflare->set_token( $token );
				$this->audit( '' === $token ? 'cloudflare_token_removed' : 'cloudflare_token_saved' );
				View::flash( 'success', '' === $token ? __( 'Cloudflare token removed.', 'sentinel-shield' ) : __( 'Cloudflare token saved.', 'sentinel-shield' ) );
				$back .= '#ss-cloudflare';
				break;
			case 'cf_test':
				$result = $cloudflare->test();
				View::flash( $result['ok'] ? 'success' : 'error', $result['message'] );
				$back .= '#ss-cloudflare';
				break;
			case 'cf_sync':
				if ( ! $cloudflare->enabled() ) {
					View::flash( 'error', __( 'Switch on "Sync blocked IPs to a Cloudflare IP list" and enter the account ID, list ID and token first.', 'sentinel-shield' ) );
				} else {
					$state = $cloudflare->sync();
					$this->audit( 'cloudflare_sync' );
					/* translators: %d: number of items. */
					View::flash( ! empty( $state['ok'] ) ? 'success' : 'error', ! empty( $state['ok'] ) ? sprintf( __( 'Synced %d items to Cloudflare.', 'sentinel-shield' ), (int) $state['count'] ) : (string) $state['error'] );
				}
				$back .= '#ss-cloudflare';
				break;
			default:
				View::flash( 'error', __( 'Unknown action.', 'sentinel-shield' ) );
		}
		View::redirect( $back );
	}

	/**
	 * Login Security tools: forget failed logins.
	 */
	public function login_security(): void {
		View::guard( 'sentinel_shield_login_security' );
		$op = isset( $_POST['op'] ) ? sanitize_key( wp_unslash( $_POST['op'] ) ) : '';
		if ( 'clear' === $op ) {
			$rows = $this->c->get( LoginAttemptRepository::class )->clear_all();
			/* translators: %d: number of records. */
			View::flash( 'success', sprintf( __( 'Forgot %d failed logins.', 'sentinel-shield' ), $rows ) );
			\SentinelShield\Support\Cached::bump();
			$this->audit( 'login_attempts_cleared', array( 'rows' => $rows ) );
		} else {
			View::flash( 'error', __( 'Unknown action.', 'sentinel-shield' ) );
		}
		View::redirect( Admin::url( 'sentinel-shield-settings', array( 'tab' => 'login' ) ) );
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

		$settings         = $this->c->get( Settings::class );
		[ $new, $errors ] = SettingsSchema::sanitize_tab( $tab, $input, $settings->network_settings() );
		if ( 'general' === $tab ) {
			$new = Settings::apply_test_mode_expiry( $new );
		}
		$new = $this->keep_own_twofa_login( $new );
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
		$limit    = 10000;
		while ( false !== ( $row = fgetcsv( $handle ) ) && $line < $limit ) { // phpcs:ignore Generic.CodeAnalysis.AssignmentInCondition.FoundInWhileCondition
			++$line;
			// Plain blocklist files work too: "#"/";" comments and blank lines are ignored, "IP <tab> notes" reads the IP.
			$value = FeedParser::plain_entry( ltrim( (string) ( $row[0] ?? '' ), "'" ) );
			if ( null === $value || ( 1 === $line && 'value' === strtolower( $value ) ) ) {
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
		$truncated = $line >= $limit && false !== fgets( $handle );
		fclose( $handle ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
		$this->c->get( RuleCache::class )->flush();
		if ( $truncated ) {
			/* translators: %d: line limit. */
			View::flash( 'warning', sprintf( __( 'Only the first %d lines were imported. For large public lists, use the Blocklists settings tab instead.', 'sentinel-shield' ), $limit ) );
		}
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
		$clean              = $this->keep_own_twofa_login( $clean );
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
				$mode                              = isset( $_POST['mode'] ) ? sanitize_key( wp_unslash( $_POST['mode'] ) ) : '';
				$all                               = $settings->network_settings();
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
				$lines   = preg_split( '/\R/', $headers );
				foreach ( false === $lines ? array() : $lines as $line ) {
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
