<?php
/**
 * Malware lockdown module: runtime hardening plus a scheduled integrity scan.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Modules;

use SentinelShield\Admin\Admin;
use SentinelShield\Container;
use SentinelShield\Lockdown\AdminRegistry;
use SentinelShield\Lockdown\Hardening;
use SentinelShield\Lockdown\IntegrityScanner;
use SentinelShield\Lockdown\UploadGuard;
use SentinelShield\Repository\EventRepository;
use SentinelShield\Settings;

defined( 'ABSPATH' ) || exit;

/**
 * Scans twice a day; new critical or warning findings are logged and emailed.
 */
final class LockdownModule implements ModuleInterface {

	public const CRON_HOOK = 'sentinel_shield_lockdown_scan';

	/**
	 * Module slug.
	 */
	public function slug(): string {
		return 'lockdown';
	}

	/**
	 * Hooks the module.
	 *
	 * @param Container $container Services.
	 */
	public function register( Container $container ): void {
		$container->get( Hardening::class )->register();
		add_action(
			self::CRON_HOOK,
			static function () use ( $container ): void {
				self::notify( $container, $container->get( IntegrityScanner::class )->run(), true );
			}
		);
		add_action(
			'init',
			static function (): void {
				if ( is_main_site() && ! wp_next_scheduled( self::CRON_HOOK ) ) {
					wp_schedule_event( time() + wp_rand( 10, 120 ) * MINUTE_IN_SECONDS, 'twicedaily', self::CRON_HOOK );
				}
			}
		);
	}

	/**
	 * Applies settings that change files or approvals. Always hooked (even with the
	 * module off) so switching the module off also removes the uploads rules.
	 *
	 * @param Container $container Services.
	 */
	public static function on_settings_saved( Container $container ): void {
		$settings = $container->get( Settings::class );
		$settings->refresh();
		$active = $settings->is_enabled() && $settings->is_module_enabled( 'lockdown' );
		UploadGuard::sync_htaccess( $active && (bool) $settings->get( 'lockdown.block_php_uploads', false ) );
		$admins = $container->get( AdminRegistry::class );
		if ( $active && $settings->get( 'lockdown.admin_lock', false ) && ! $admins->approvals() ) {
			// First switch-on: approve the admins the Users screen shows, never hidden ones.
			$admins->approve_visible( get_current_user_id() );
		}
	}

	/**
	 * Logs new findings and, for scheduled scans, emails them.
	 *
	 * @param Container            $container Services.
	 * @param array<string, mixed> $report    Scan report.
	 * @param bool                 $email     Whether to send the email.
	 */
	public static function notify( Container $container, array $report, bool $email ): void {
		$new = array_values( array_filter( (array) $report['findings'], static fn( array $f ): bool => in_array( $f['id'], (array) $report['new'], true ) ) );
		if ( ! $new ) {
			return;
		}
		$events = $container->get( EventRepository::class );
		foreach ( array_slice( $new, 0, 20 ) as $finding ) {
			$events->log(
				'malware_finding',
				array(
					'module'  => 'lockdown',
					'reason'  => mb_substr( strtoupper( (string) $finding['severity'] ) . ': ' . $finding['title'], 0, 255 ),
					'context' => array(
						'check' => $finding['check'],
						'id'    => $finding['id'],
					),
				)
			);
		}
		if ( ! $email || ! $container->get( Settings::class )->get( 'lockdown.scan_email', true ) ) {
			return;
		}
		$lines = array(
			/* translators: %s: site URL. */
			sprintf( __( 'The Sentinel Shield malware scan found new problems on %s:', 'sentinel-shield' ), home_url( '/' ) ),
			'',
		);
		foreach ( array_slice( $new, 0, 30 ) as $finding ) {
			$lines[] = '- [' . strtoupper( (string) $finding['severity'] ) . '] ' . $finding['title'];
		}
		$lines[] = '';
		$lines[] = __( 'Review them (and approve anything you recognize) here:', 'sentinel-shield' );
		$lines[] = Admin::url( 'sentinel-shield-lockdown' );
		wp_mail(
			(string) get_site_option( 'admin_email' ),
			/* translators: %s: site name. */
			sprintf( __( '[%s] Malware scan: new findings', 'sentinel-shield' ), wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ) ),
			implode( "\n", $lines )
		);
	}
}
