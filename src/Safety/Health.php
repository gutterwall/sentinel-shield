<?php
/**
 * Enforcement health: is protection actually working right now?
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Safety;

use SentinelShield\Container;
use SentinelShield\Cron\CronInspector;
use SentinelShield\Feeds\FeedCatalog;
use SentinelShield\Firewall\CloudflareSync;
use SentinelShield\Firewall\EarlyGate;
use SentinelShield\Feeds\FeedUpdater;
use SentinelShield\Geo\CountryDatabase;
use SentinelShield\Lockdown\FileIntegrity;
use SentinelShield\Lockdown\IntegrityScanner;
use SentinelShield\Modules\MaintenanceModule;
use SentinelShield\Settings;
use SentinelShield\Support\Mutex;
use SentinelShield\Audit\AuditExporter;
use SentinelShield\Support\DataDir;
use SentinelShield\Support\Mailer;

defined( 'ABSPATH' ) || exit;

/**
 * Settings say what should happen; this checks whether it does: protection
 * switched on and out of test mode, IP detection sound, locks working,
 * scheduled jobs running on time, blocklists and the country database fresh,
 * and scans clean. Each check is ok, warn (degraded), bad (not protected, or
 * a problem found) or info.
 */
final class Health {

	/**
	 * Constructor.
	 *
	 * @param Container $c Services.
	 */
	public function __construct( private Container $c ) {}

	/**
	 * All checks.
	 *
	 * @param array<string, mixed>|null $details Client IP details of the current request (null outside a web request).
	 * @return list<array{id:string, label:string, state:string, detail:string}>
	 */
	public function checks( ?array $details = null ): array {
		$settings = $this->c->get( Settings::class );
		$rows     = array();
		$add      = static function ( string $id, string $label, string $state, string $detail ) use ( &$rows ): void {
			$rows[] = array(
				'id'     => $id,
				'label'  => $label,
				'state'  => $state,
				'detail' => $detail,
			);
		};

		// Protection and test mode.
		if ( SafetyGuard::emergency_disabled() ) {
			$add( 'enabled', __( 'Protection', 'sentinel-shield' ), 'bad', __( 'SENTINEL_SHIELD_DISABLE is set in wp-config.php: nothing is enforced.', 'sentinel-shield' ) );
		} elseif ( ! $settings->is_enabled() ) {
			$add( 'enabled', __( 'Protection', 'sentinel-shield' ), 'bad', __( 'Protection is switched off on the General tab: nothing is enforced.', 'sentinel-shield' ) );
		} elseif ( $settings->global_test_mode() ) {
			$until = (int) $settings->get( 'general.test_mode_until', 0 );
			$add(
				'enabled',
				__( 'Protection', 'sentinel-shield' ),
				'warn',
				$until > time()
					/* translators: %s: date and time. */
					? sprintf( __( 'Test mode until %s: blocks and lockouts are only logged.', 'sentinel-shield' ), wp_date( 'Y-m-d H:i', $until ) )
					: __( 'Test mode with no end date (new installations start this way): blocks and lockouts are only logged. Turn it off on the General tab once IP detection is right, or give it an end date.', 'sentinel-shield' )
			);
		} else {
			$testing = array();
			foreach ( Settings::MODULES as $module ) {
				if ( $settings->is_module_enabled( $module ) && 'on' === $settings->get( "modules.$module.test_mode", 'inherit' ) ) {
					$testing[] = $module;
				}
			}
			$add(
				'enabled',
				__( 'Protection', 'sentinel-shield' ),
				$testing ? 'warn' : 'ok',
				$testing
					/* translators: %s: list of modules. */
					? sprintf( __( 'Enforcing, except modules in test mode: %s.', 'sentinel-shield' ), implode( ', ', $testing ) )
					: __( 'Enforcing.', 'sentinel-shield' )
			);
		}

		// IP detection, judged on the current request.
		if ( null !== $details ) {
			$warnings = $this->c->get( SafetyGuard::class )->detection_warnings( $details );
			$add( 'ip', __( 'IP detection', 'sentinel-shield' ), $warnings ? 'warn' : 'ok', $warnings ? implode( ' ', $warnings ) : __( 'Your request was identified correctly.', 'sentinel-shield' ) );
		}

		// Locks.
		$lock = Mutex::status();
		if ( null === $lock || 'native' === $lock['mode'] ) {
			$add( 'locks', __( 'Concurrency locks', 'sentinel-shield' ), 'ok', __( 'Database named locks work.', 'sentinel-shield' ) );
		} elseif ( 'row' === $lock['mode'] ) {
			$add( 'locks', __( 'Concurrency locks', 'sentinel-shield' ), 'warn', __( 'The database gives no named locks (a database proxy, cluster or non-MySQL database), so lock rows in the options table are used instead. This works but is slower; if you use a proxy such as ProxySQL, let it pass GET_LOCK through.', 'sentinel-shield' ) );
		} else {
			/* translators: 1: date and time, 2: database error. */
			$add( 'locks', __( 'Concurrency locks', 'sentinel-shield' ), 'bad', sprintf( __( 'No lock could be taken at %1$s (%2$s). Logins, code checks and unlock requests that need a lock are refused until this works again.', 'sentinel-shield' ), wp_date( 'Y-m-d H:i', (int) $lock['time'] ), '' === $lock['error'] ? __( 'no error reported', 'sentinel-shield' ) : $lock['error'] ) );
		}

		// Scheduled jobs.
		$cron = CronInspector::health( CronInspector::events() );
		$scan = IntegrityScanner::report();
		$late = array();
		if ( null === $scan || (int) $scan['time'] < time() - 26 * HOUR_IN_SECONDS ) {
			$late[] = __( 'malware scan (twice a day)', 'sentinel-shield' );
		}
		if ( $settings->get( 'lockdown.integrity_checks', true ) ) {
			$integrity = FileIntegrity::report();
			if ( null === $integrity || (int) $integrity['time'] < time() - 3 * DAY_IN_SECONDS ) {
				$late[] = __( 'file integrity check (daily)', 'sentinel-shield' );
			}
		}
		if ( (int) get_site_option( MaintenanceModule::LAST_RUN, 0 ) < time() - 3 * HOUR_IN_SECONDS ) {
			$late[] = __( 'maintenance (hourly)', 'sentinel-shield' );
		}
		if ( $late || $cron['overdue'] > 0 ) {
			$detail = $late
				/* translators: %s: list of jobs. */
				? sprintf( __( 'Not run recently: %s.', 'sentinel-shield' ), implode( ', ', $late ) )
				: '';
			if ( $cron['overdue'] > 0 ) {
				/* translators: %d: number of tasks. */
				$detail .= ' ' . sprintf( _n( '%d scheduled task is overdue.', '%d scheduled tasks are overdue.', $cron['overdue'], 'sentinel-shield' ), $cron['overdue'] );
			}
			if ( $cron['disabled'] ) {
				$detail .= ' ' . __( 'DISABLE_WP_CRON is set: check that a server cron job calls wp-cron.php.', 'sentinel-shield' );
			}
			$add( 'cron', __( 'Scheduled jobs', 'sentinel-shield' ), 'warn', trim( $detail . ' ' . __( 'New sites need a day before every job has run once.', 'sentinel-shield' ) ) );
		} else {
			$add( 'cron', __( 'Scheduled jobs', 'sentinel-shield' ), 'ok', __( 'Scans and maintenance run on time.', 'sentinel-shield' ) );
		}

		// Blocklists.
		$slugs = $settings->is_module_enabled( 'feeds' ) ? FeedCatalog::enabled_slugs( $settings ) : array();
		if ( $slugs ) {
			$updater = $this->c->get( FeedUpdater::class );
			$state   = $updater->state();
			$stale   = array();
			foreach ( $slugs as $slug ) {
				$entry = (array) ( $state[ $slug ] ?? array() );
				if ( empty( $entry['last_success'] ) || (int) $entry['last_success'] < time() - 3 * $updater->interval( $slug ) ) {
					$stale[] = FeedCatalog::NAMES[ $slug ] ?? $slug;
				}
			}
			$add(
				'feeds',
				__( 'Blocklists', 'sentinel-shield' ),
				$stale ? 'warn' : 'ok',
				$stale
					/* translators: %s: list of blocklists. */
					? sprintf( __( 'Not updated for a long time (or never): %s. See the Blocklists tab for the last error.', 'sentinel-shield' ), implode( ', ', $stale ) )
					: __( 'Every enabled list is up to date.', 'sentinel-shield' )
			);
		}

		// Early firewall and edge blocking.
		$gate = $this->c->get( EarlyGate::class );
		if ( $gate->wanted() && ! DataDir::ready() ) {
			$add( 'private', __( 'Private folder', 'sentinel-shield' ), 'bad', DataDir::problem() . ' ' . __( 'The early firewall, server files and block log are not written until this is fixed.', 'sentinel-shield' ) );
		}
		if ( 'off' !== $gate->mode() ) {
			$snap  = (array) get_site_option( EarlyGate::STATE, array() );
			$issue = '';
			if ( ! $snap || ! is_file( EarlyGate::path() ) ) {
				$issue = __( 'No snapshot yet; it is written on the next settings save or hourly.', 'sentinel-shield' );
			} elseif ( ! empty( $snap['error'] ) ) {
				$issue = (string) $snap['error'];
			} elseif ( (int) $snap['valid_until'] < time() ) {
				$issue = __( 'The snapshot is out of date, so the early firewall lets everything through to WordPress until it is rebuilt. Check that scheduled jobs run.', 'sentinel-shield' );
			} elseif ( 'mu_plugin' === $gate->mode() && ! EarlyGate::is_own_loader( EarlyGate::loader_path() ) ) {
				$issue = __( 'The must-use loader is missing; save the Server & CDN settings again (the mu-plugins folder must be writable).', 'sentinel-shield' );
			} elseif ( null !== $details && '' === EarlyGate::active_as() ) {
				$issue = 'prepend' === $gate->mode() ? __( 'Not running: add the auto_prepend_file line shown on the Server & CDN tab and restart PHP.', 'sentinel-shield' ) : __( 'Not running for this request.', 'sentinel-shield' );
			}
			$add( 'early', __( 'Early firewall', 'sentinel-shield' ), '' === $issue ? 'ok' : 'warn', '' === $issue ? __( 'Running with a current snapshot.', 'sentinel-shield' ) : $issue );
		}
		$legacy = EarlyGate::legacy_state();
		if ( ! empty( $legacy['failed'] ) ) {
			/* translators: %s: file paths. */
			$add( 'legacy', __( 'Old runtime files', 'sentinel-shield' ), 'bad', sprintf( __( 'Could not remove files left in the public uploads folder by version 0.8.0: %s. Delete them by hand.', 'sentinel-shield' ), implode( ', ', array_map( 'strval', (array) $legacy['failed'] ) ) ) );
		}
		$cf_state = CloudflareSync::state();
		if ( ! empty( $cf_state['retired'] ) || ( ! $settings->get( 'cloudflare.sync', false ) && in_array( $cf_state['status'] ?? '', array( 'failed', 'unknown', 'applying' ), true ) ) ) {
			$add( 'cloudflare_cleanup', __( 'Cloudflare cleanup', 'sentinel-shield' ), 'warn', __( 'A Cloudflare list is not confirmed empty yet; its blocks may still be active at Cloudflare. See Settings → Server & CDN.', 'sentinel-shield' ) );
		}
		if ( $settings->get( 'cloudflare.sync', false ) ) {
			$cf     = CloudflareSync::state();
			$status = (string) ( $cf['status'] ?? '' );
			$fine   = in_array( $status, array( 'active', 'empty' ), true ) || ( 'applying' === $status && (int) ( $cf['time'] ?? 0 ) > time() - 10 * MINUTE_IN_SECONDS );
			$add(
				'cloudflare',
				__( 'Cloudflare IP list', 'sentinel-shield' ),
				$fine ? 'ok' : 'warn',
				$fine
					/* translators: 1: date, 2: count. */
					? sprintf( __( 'Applied %1$s (%2$d items).', 'sentinel-shield' ), wp_date( 'Y-m-d H:i', (int) $cf['time'] ), (int) $cf['count'] )
					: ( empty( $cf ) ? __( 'Not synced yet.', 'sentinel-shield' ) : ( '' !== (string) ( $cf['error'] ?? '' ) ? (string) $cf['error'] : __( 'Cloudflare has not confirmed the last update.', 'sentinel-shield' ) ) )
			);
		}

		// Alerts actually leaving the site.
		$failing = array_values( array_filter( array( 'alert', 'code', 'unlock' ), array( Mailer::class, 'failing' ) ) );
		$add(
			'mail',
			__( 'Alert emails', 'sentinel-shield' ),
			$failing ? 'bad' : 'ok',
			$failing
				/* translators: 1: kinds of email, 2: error. */
				? sprintf( __( 'The mail system refused the last message for: %1$s (%2$s). Alerts and codes may not reach anyone; see Settings → Alerts & Audit Log.', 'sentinel-shield' ), implode( ', ', $failing ), (string) ( Mailer::health()[ $failing[0] ]['error'] ?? '' ) )
				: __( 'Recent messages were accepted by the mail system (arrival in the inbox cannot be checked).', 'sentinel-shield' )
		);
		$audit = AuditExporter::state();
		if ( '' !== (string) $settings->get( 'audit.webhook_url', '' ) ) {
			$stuck = ! empty( $audit['failures'] ) && (int) ( $audit['failed'] ?? 0 ) - (int) ( $audit['last_ok'] ?? 0 ) > HOUR_IN_SECONDS;
			$add(
				'audit',
				__( 'Remote audit log', 'sentinel-shield' ),
				$stuck ? 'warn' : 'ok',
				$stuck
					/* translators: %s: error. */
					? sprintf( __( 'Deliveries have been failing for over an hour: %s. Events are kept and sent when the endpoint works again.', 'sentinel-shield' ), (string) ( $audit['error'] ?? '' ) )
					: __( 'Events are being delivered.', 'sentinel-shield' )
			);
		}
		$beat = (array) ( $audit['heartbeat'] ?? array() );
		if ( '' !== (string) $settings->get( 'audit.heartbeat_url', '' ) && $beat && empty( $beat['ok'] ) ) {
			/* translators: %s: error. */
			$add( 'heartbeat', __( 'Heartbeat', 'sentinel-shield' ), 'warn', sprintf( __( 'The last ping failed: %s.', 'sentinel-shield' ), (string) $beat['error'] ) );
		}

		// Country database.
		if ( $settings->is_module_enabled( 'geo_login' ) && 'off' !== $settings->get( 'geo.mode', 'off' ) && $settings->get( 'geo.dbip', false ) ) {
			$info = $this->c->get( CountryDatabase::class )->info();
			$add(
				'geo',
				__( 'Country database', 'sentinel-shield' ),
				null === $info ? 'warn' : 'ok',
				null === $info ? __( 'Not downloaded yet: logins whose country is unknown follow your "unknown country" rule.', 'sentinel-shield' ) : __( 'Installed.', 'sentinel-shield' )
			);
		}

		// Scan results.
		$alerts = 0;
		foreach ( array( $scan, FileIntegrity::report() ) as $report ) {
			$alerts += count( array_filter( (array) ( $report['findings'] ?? array() ), array( IntegrityScanner::class, 'is_alert' ) ) );
		}
		$add(
			'findings',
			__( 'Scan findings', 'sentinel-shield' ),
			$alerts ? 'bad' : 'ok',
			$alerts
				/* translators: %d: number of findings. */
				? sprintf( _n( '%d finding needs attention on the Malware Lockdown page.', '%d findings need attention on the Malware Lockdown page.', $alerts, 'sentinel-shield' ), $alerts )
				: __( 'No open critical findings or warnings.', 'sentinel-shield' )
		);

		// Persistent object cache.
		$add(
			'cache',
			__( 'Persistent object cache', 'sentinel-shield' ),
			'info',
			wp_using_ext_object_cache()
				? __( 'In use: rule matches and hit counts are cached between requests.', 'sentinel-shield' )
				: __( 'Not in use. Everything works; blocked-request hit counts are then approximate (at most one per IP per minute), and a cache such as Redis would take more load off the database during attacks.', 'sentinel-shield' )
		);
		return $rows;
	}

	/**
	 * The worst state among the checks (bad, warn or ok).
	 *
	 * @param list<array{state:string}> $checks Checks.
	 */
	public static function overall( array $checks ): string {
		$states = array_column( $checks, 'state' );
		if ( in_array( 'bad', $states, true ) ) {
			return 'bad';
		}
		return in_array( 'warn', $states, true ) ? 'warn' : 'ok';
	}
}
