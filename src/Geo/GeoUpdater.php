<?php
/**
 * Downloads DB-IP's free country database and keeps it current.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Geo;

use SentinelShield\Repository\EventRepository;
use SentinelShield\Settings;

defined( 'ABSPATH' ) || exit;

/**
 * DB-IP publishes "IP to Country Lite" (CC BY 4.0) on the first of each month at
 * a URL containing the month. A daily tick checks whether a weekly check is due;
 * an unchanged file is not downloaded again (ETag / Last-Modified). Early in a
 * month, before the new edition is out, the previous month's file is used.
 * A failed or implausibly small download never replaces a working database.
 */
final class GeoUpdater {

	public const CRON_HOOK    = 'sentinel_shield_geo_update';
	public const STATE_OPTION = 'sentinel_shield_geo_db';
	public const URL          = 'https://download.db-ip.com/free/dbip-country-lite-%s.csv.gz';
	public const ATTRIBUTION  = 'https://db-ip.com';

	private const CHECK_EVERY = WEEK_IN_SECONDS;
	private const MAX_BYTES   = 64 * 1024 * 1024;

	/**
	 * Constructor.
	 *
	 * @param Settings        $settings   Settings.
	 * @param CountryDatabase $db         Database file.
	 * @param EventRepository $events     Event log.
	 * @param int             $min_ranges Fewest ranges a plausible database has.
	 */
	public function __construct( private Settings $settings, private CountryDatabase $db, private EventRepository $events, private int $min_ranges = 100000 ) {}

	/**
	 * Folder for the database: uploads/sentinel-shield of the main site.
	 */
	public static function dir(): string {
		$switched = is_multisite() && ! is_main_site();
		if ( $switched ) {
			switch_to_blog( get_main_site_id() );
		}
		$base = (string) wp_upload_dir( null, false )['basedir'];
		if ( $switched ) {
			restore_current_blog();
		}
		return trailingslashit( $base ) . 'sentinel-shield';
	}

	/**
	 * Path of the database file.
	 */
	public static function path(): string {
		return self::dir() . '/geo-country.bin';
	}

	/**
	 * Whether automatic downloads are switched on.
	 */
	public function enabled(): bool {
		return $this->settings->is_enabled() && $this->settings->is_module_enabled( 'geo_login' ) && (bool) $this->settings->get( 'geo.dbip', false );
	}

	/**
	 * Download status.
	 *
	 * @return array<string, mixed>
	 */
	public function state(): array {
		$state = get_site_option( self::STATE_OPTION, array() );
		return is_array( $state ) ? $state : array();
	}

	/**
	 * Whether a check is due.
	 */
	public function due(): bool {
		return $this->enabled() && ( null === $this->db->info() || time() >= (int) ( $this->state()['next_due'] ?? 0 ) );
	}

	/**
	 * Cron entry point.
	 */
	public function tick(): void {
		if ( $this->due() ) {
			$this->update();
		}
	}

	/**
	 * Schedules a one-off update shortly (after switching downloads on).
	 *
	 * @param int $delay Seconds from now.
	 */
	public static function schedule_soon( int $delay ): void {
		if ( ! wp_next_scheduled( self::CRON_HOOK, array( 'soon' ) ) ) {
			wp_schedule_single_event( time() + $delay, self::CRON_HOOK, array( 'soon' ) );
		}
	}

	/**
	 * Downloads and installs the current edition.
	 *
	 * @param bool $force Download even if unchanged.
	 * @return array<string, mixed>|\WP_Error New state, or the error (the old database stays).
	 */
	public function update( bool $force = false ): array|\WP_Error {
		if ( ! function_exists( 'wp_tempnam' ) ) {
			require_once ABSPATH . 'wp-admin/includes/file.php';
		}
		$state = $this->state();
		$tmp   = wp_tempnam( 'sentinel-geo' );
		$error = null;
		$month = '';
		$code  = 0;
		// This month's edition, else last month's (the new one appears on the 1st).
		foreach ( array( gmdate( 'Y-m' ), gmdate( 'Y-m', strtotime( 'first day of last month' ) ) ) as $month ) {
			$url     = sprintf( self::URL, $month );
			$headers = array();
			if ( ! $force && null !== $this->db->info() && ( $state['url'] ?? '' ) === $url ) {
				$headers = array_filter(
					array(
						'If-None-Match'     => (string) ( $state['etag'] ?? '' ),
						'If-Modified-Since' => (string) ( $state['modified'] ?? '' ),
					)
				);
			}
			$response = wp_safe_remote_get(
				$url,
				array(
					'timeout'             => 60,
					'redirection'         => 3,
					'user-agent'          => 'SentinelShield/' . ( defined( 'SENTINEL_SHIELD_VERSION' ) ? SENTINEL_SHIELD_VERSION : '0' ),
					'headers'             => $headers,
					'stream'              => true,
					'filename'            => $tmp,
					'limit_response_size' => self::MAX_BYTES,
				)
			);
			if ( is_wp_error( $response ) ) {
				$error = $response;
				break;
			}
			$code = (int) wp_remote_retrieve_response_code( $response );
			if ( 404 === $code ) {
				continue;
			}
			if ( 200 !== $code && 304 !== $code ) {
				/* translators: 1: HTTP status code, 2: URL. */
				$error = new \WP_Error( 'sentinel_shield_geo_http', sprintf( __( 'HTTP %1$d from %2$s.', 'sentinel-shield' ), $code, $url ) );
			}
			break;
		}
		if ( null === $error && 404 === $code ) {
			$error = new \WP_Error( 'sentinel_shield_geo_http', __( 'The DB-IP country database for this month and last month was not found.', 'sentinel-shield' ) );
		}

		if ( null === $error && 304 === $code ) {
			wp_delete_file( $tmp );
			$state['last_check'] = time();
			return $this->succeed( $state );
		}
		if ( null === $error ) {
			$built = $this->install( $tmp );
			if ( is_wp_error( $built ) ) {
				$error = $built;
			} else {
				$state = array_merge(
					$state,
					$built,
					array(
						'month'      => $month,
						'url'        => sprintf( self::URL, $month ),
						'etag'       => (string) wp_remote_retrieve_header( $response, 'etag' ),
						'modified'   => (string) wp_remote_retrieve_header( $response, 'last-modified' ),
						'last_check' => time(),
						'updated'    => time(),
					)
				);
			}
		}
		wp_delete_file( $tmp );
		if ( null !== $error ) {
			return $this->fail( $state, $error );
		}
		$this->events->log(
			'geo_db_updated',
			array(
				'module'  => 'geo_login',
				/* translators: 1: month, 2: number of IPv4 ranges, 3: number of IPv6 ranges. */
				'reason'  => sprintf( __( 'Country database %1$s installed: %2$s IPv4 and %3$s IPv6 ranges', 'sentinel-shield' ), $month, number_format_i18n( (int) $state['v4'] ), number_format_i18n( (int) $state['v6'] ) ),
				'context' => array( 'month' => $month ),
			)
		);
		return $this->succeed( $state );
	}

	/**
	 * Builds the database from a downloaded CSV and swaps it in if plausible.
	 *
	 * @param string $csv Downloaded file.
	 * @return array{v4:int, v6:int}|\WP_Error
	 */
	public function install( string $csv ): array|\WP_Error {
		$dir = self::dir();
		if ( ! wp_mkdir_p( dirname( $this->db->path() ) ) ) {
			/* translators: %s: folder. */
			return new \WP_Error( 'sentinel_shield_geo_dir', sprintf( __( 'Cannot create the folder %s.', 'sentinel-shield' ), $dir ) );
		}
		self::protect_dir( dirname( $this->db->path() ) );
		$new = $this->db->path() . '.new';
		try {
			$counts = CountryDatabase::build( $csv, $new );
		} catch ( \RuntimeException $e ) {
			if ( is_file( $new ) ) {
				wp_delete_file( $new );
			}
			/* translators: %s: error message. */
			return new \WP_Error( 'sentinel_shield_geo_build', sprintf( __( 'The downloaded country database is invalid: %s', 'sentinel-shield' ), $e->getMessage() ) );
		}
		if ( $counts['v4'] + $counts['v6'] < $this->min_ranges ) {
			wp_delete_file( $new );
			/* translators: %d: number of ranges. */
			return new \WP_Error( 'sentinel_shield_geo_small', sprintf( __( 'The downloaded country database has only %d ranges, so it looks incomplete. The previous database is kept.', 'sentinel-shield' ), $counts['v4'] + $counts['v6'] ) );
		}
		CountryDatabase::close( $this->db->path() );
		if ( ! rename( $new, $this->db->path() ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.rename_rename -- Atomic swap within one folder.
			wp_delete_file( $new );
			return new \WP_Error( 'sentinel_shield_geo_write', __( 'Cannot replace the country database file.', 'sentinel-shield' ) );
		}
		return array(
			'v4' => $counts['v4'],
			'v6' => $counts['v6'],
		);
	}

	/**
	 * Deletes the database and its status (downloads switched off, or uninstall).
	 */
	public function purge(): void {
		$this->db->delete();
		delete_site_option( self::STATE_OPTION );
	}

	/**
	 * Keeps the folder from being listed or served directly.
	 *
	 * @param string $dir Folder.
	 */
	private static function protect_dir( string $dir ): void {
		$files = array(
			'index.php' => "<?php\n// Silence is golden.\n",
			'.htaccess' => "Require all denied\n",
		);
		foreach ( $files as $name => $content ) {
			if ( ! is_file( "$dir/$name" ) ) {
				file_put_contents( "$dir/$name", $content ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Tiny guard files in our own folder.
			}
		}
	}

	/**
	 * Records success and schedules the next check with jitter.
	 *
	 * @param array<string, mixed> $state Status.
	 * @return array<string, mixed>
	 */
	private function succeed( array $state ): array {
		$state['error']    = '';
		$state['failures'] = 0;
		$state['next_due'] = time() + self::CHECK_EVERY + wp_rand( 0, 6 * HOUR_IN_SECONDS );
		update_site_option( self::STATE_OPTION, $state );
		return $state;
	}

	/**
	 * Records a failure and backs off: 1 h, 2 h, 4 h ... up to a day.
	 *
	 * @param array<string, mixed> $state Status.
	 * @param \WP_Error            $error Error.
	 */
	private function fail( array $state, \WP_Error $error ): \WP_Error {
		$failures            = (int) ( $state['failures'] ?? 0 ) + 1;
		$state['failures']   = $failures;
		$state['error']      = $error->get_error_message();
		$state['last_check'] = time();
		$state['next_due']   = time() + min( DAY_IN_SECONDS, HOUR_IN_SECONDS * ( 2 ** min( $failures - 1, 5 ) ) );
		update_site_option( self::STATE_OPTION, $state );
		$this->events->log(
			'geo_db_error',
			array(
				'module'  => 'geo_login',
				'reason'  => mb_substr( $error->get_error_message(), 0, 255 ),
				'context' => array( 'failures' => $failures ),
			)
		);
		return $error;
	}
}
