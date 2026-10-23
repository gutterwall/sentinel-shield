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
use SentinelShield\Lockdown\FileIntegrity;
use SentinelShield\Lockdown\Hardening;
use SentinelShield\Lockdown\IntegrityScanner;
use SentinelShield\Lockdown\RequestGuard;
use SentinelShield\Lockdown\UploadGuard;
use SentinelShield\Repository\EventRepository;
use SentinelShield\Settings;
use SentinelShield\Support\Mailer;

defined( 'ABSPATH' ) || exit;

/**
 * Scans twice a day and verifies file checksums daily; new critical or warning
 * findings are logged and emailed. Both jobs continue in follow-up runs a
 * minute or two apart when one run cannot finish them.
 */
final class LockdownModule implements ModuleInterface {

	public const CRON_HOOK          = 'sentinel_shield_lockdown_scan';
	public const CONTINUE_HOOK      = 'sentinel_shield_lockdown_scan_continue';
	public const INTEGRITY_HOOK     = 'sentinel_shield_integrity_check';
	public const INTEGRITY_CONTINUE = 'sentinel_shield_integrity_continue';
	public const CRON_HOOKS         = array( self::CRON_HOOK, self::CONTINUE_HOOK, self::INTEGRITY_HOOK, self::INTEGRITY_CONTINUE );
	public const INTEGRITY_BUDGET   = 15.0;

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
		$container->get( RequestGuard::class )->enforce();
		$container->get( Hardening::class )->register();
		$scan = static function () use ( $container ): void {
			self::after_scan( $container, $container->get( IntegrityScanner::class )->run(), true );
		};
		add_action( self::CRON_HOOK, $scan );
		add_action( self::CONTINUE_HOOK, $scan );
		add_action(
			self::INTEGRITY_HOOK,
			static function () use ( $container ): void {
				if ( self::integrity_enabled( $container ) ) {
					$container->get( FileIntegrity::class )->start();
					self::integrity_step( $container, self::INTEGRITY_BUDGET, true );
				}
			}
		);
		add_action(
			self::INTEGRITY_CONTINUE,
			static function () use ( $container ): void {
				self::integrity_step( $container, self::INTEGRITY_BUDGET, true );
			}
		);
		add_action(
			'init',
			static function () use ( $container ): void {
				if ( ! is_main_site() ) {
					return;
				}
				if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
					wp_schedule_event( time() + wp_rand( 10, 120 ) * MINUTE_IN_SECONDS, 'twicedaily', self::CRON_HOOK );
				}
				if ( self::integrity_enabled( $container ) && ! wp_next_scheduled( self::INTEGRITY_HOOK ) ) {
					wp_schedule_event( time() + wp_rand( 30, 300 ) * MINUTE_IN_SECONDS, 'daily', self::INTEGRITY_HOOK );
				}
			}
		);
	}

	/**
	 * Whether the daily checksum verification is switched on.
	 *
	 * @param Container $container Services.
	 */
	public static function integrity_enabled( Container $container ): bool {
		return (bool) $container->get( Settings::class )->get( 'lockdown.integrity_checks', true );
	}

	/**
	 * Notifies about a malware scan run and schedules its continuation.
	 *
	 * @param Container            $container Services.
	 * @param array<string, mixed> $report    Scan report.
	 * @param bool                 $email     Whether to email new findings.
	 */
	public static function after_scan( Container $container, array $report, bool $email ): void {
		self::notify( $container, $report, $email );
		if ( empty( $report['complete'] ) && ! wp_next_scheduled( self::CONTINUE_HOOK ) ) {
			wp_schedule_single_event( time() + 2 * MINUTE_IN_SECONDS, self::CONTINUE_HOOK );
		}
	}

	/**
	 * Runs one slice of the checksum verification; notifies when the pass
	 * completes, otherwise schedules the next slice.
	 *
	 * @param Container $container Services.
	 * @param float     $budget    Seconds.
	 * @param bool      $email     Whether to email new findings.
	 * @return array<string, mixed> FileIntegrity::step() result.
	 */
	public static function integrity_step( Container $container, float $budget, bool $email ): array {
		$result = $container->get( FileIntegrity::class )->step( $budget );
		if ( $result['done'] && is_array( $result['report'] ) && ! $result['busy'] ) {
			self::notify( $container, $result['report'], $email, 'integrity' );
		} elseif ( ! $result['done'] && ! wp_next_scheduled( self::INTEGRITY_CONTINUE ) ) {
			wp_schedule_single_event( time() + MINUTE_IN_SECONDS, self::INTEGRITY_CONTINUE );
		}
		return $result;
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
	 * @param string               $source    scan or integrity.
	 */
	public static function notify( Container $container, array $report, bool $email, string $source = 'scan' ): void {
		$new = array_values( array_filter( (array) $report['findings'], static fn( array $f ): bool => in_array( $f['id'], (array) $report['new'], true ) ) );
		if ( ! $new ) {
			return;
		}
		$events = $container->get( EventRepository::class );
		foreach ( array_slice( $new, 0, 20 ) as $finding ) {
			$events->log(
				'integrity' === $source ? 'integrity_finding' : 'malware_finding',
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
			'integrity' === $source
				/* translators: %s: site URL. */
				? sprintf( __( 'The Sentinel Shield file integrity check found files on %s that differ from WordPress.org:', 'sentinel-shield' ), home_url( '/' ) )
				/* translators: %s: site URL. */
				: sprintf( __( 'The Sentinel Shield malware scan found new problems on %s:', 'sentinel-shield' ), home_url( '/' ) ),
			'',
		);
		foreach ( array_slice( $new, 0, 30 ) as $finding ) {
			$lines[] = '- [' . strtoupper( (string) $finding['severity'] ) . '] ' . $finding['title'];
		}
		$lines[] = '';
		$lines[] = __( 'Review them (and approve anything you recognize) here:', 'sentinel-shield' );
		$lines[] = Admin::url( 'sentinel-shield-lockdown' );
		Mailer::send(
			(string) get_site_option( 'admin_email' ),
			'integrity' === $source
				/* translators: %s: site name. */
				? sprintf( __( '[%s] File integrity: changed files found', 'sentinel-shield' ), wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ) )
				/* translators: %s: site name. */
				: sprintf( __( '[%s] Malware scan: new findings', 'sentinel-shield' ), wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ) ),
			implode( "\n", $lines ),
			'alert'
		);
	}
}
