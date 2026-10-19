<?php
/**
 * A private folder for runtime files the web server must not serve.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Support;

defined( 'ABSPATH' ) || exit;

/**
 * The early firewall's snapshot (which includes allowlisted administrator
 * addresses), its block log (IP addresses, paths, browsers) and the generated
 * server configuration must not be downloadable. .htaccess rules only work on
 * Apache, so these files live outside the web root:
 *
 * 1. SENTINEL_SHIELD_DATA_DIR in wp-config.php, if defined;
 * 2. otherwise a "sentinel-shield-data" folder next to the WordPress folder.
 *
 * A folder counts as private only on positive evidence:
 *
 * - it is outside the web server's document root (seen in a web request), or
 * - it is inside it, and a test file there is refused (403/404) while a control
 *   file in uploads is served normally, over a verified TLS connection. This
 *   HTTP evidence is re-checked every day.
 *
 * Anything else (document root never seen, no URL can be derived, the site
 * cannot reach itself, a challenge page or login wall) is "unknown", and the
 * files are not written. The admin screens say why.
 */
final class DataDir {

	public const OPTION = 'sentinel_shield_data_dir';
	public const ROOT   = 'sentinel_shield_document_root';
	public const NAME   = 'sentinel-shield-data';

	/**
	 * How long HTTP evidence of privacy is trusted, and how often an unknown or
	 * public result is looked at again.
	 */
	public const PROBE_LIFE = DAY_IN_SECONDS;
	public const RETRY      = HOUR_IN_SECONDS;

	/**
	 * The folder (not necessarily existing yet).
	 */
	public static function path(): string {
		if ( defined( 'SENTINEL_SHIELD_DATA_DIR' ) && is_string( SENTINEL_SHIELD_DATA_DIR ) && '' !== SENTINEL_SHIELD_DATA_DIR ) {
			return untrailingslashit( wp_normalize_path( SENTINEL_SHIELD_DATA_DIR ) );
		}
		/**
		 * Filters the private data folder (no trailing slash).
		 *
		 * @param string $path Default: next to the WordPress folder.
		 */
		return untrailingslashit( wp_normalize_path( (string) apply_filters( 'sentinel_shield_data_dir', dirname( untrailingslashit( ABSPATH ) ) . '/' . self::NAME ) ) );
	}

	/**
	 * Remembers the web server's document root from a web request, so checks
	 * made from WP-CLI or cron (which have none) can use it.
	 */
	public static function remember_document_root(): void {
		$root = self::server_root();
		if ( '' !== $root && get_site_option( self::ROOT ) !== $root ) {
			update_site_option( self::ROOT, $root );
		}
	}

	/**
	 * The document root: this request's, or the last one seen in a web request.
	 */
	public static function document_root(): string {
		$root = self::server_root();
		return '' !== $root ? $root : (string) get_site_option( self::ROOT, '' );
	}

	/**
	 * Whether the folder is confirmed private: true, false (downloadable) or
	 * null (not confirmed). Remembered; evidence from an HTTP test expires after
	 * a day, a negative or unknown result is looked at again after an hour, and
	 * a changed document root always means a new check.
	 */
	public static function is_private(): ?bool {
		$path   = self::path();
		$stored = get_site_option( self::OPTION );
		if ( is_array( $stored ) && ( $stored['path'] ?? '' ) === $path && array_key_exists( 'private', $stored ) && is_dir( $path ) ) {
			$age    = time() - (int) ( $stored['checked'] ?? 0 );
			$method = (string) ( $stored['method'] ?? '' );
			$fresh  = match ( true ) {
				true !== $stored['private'] => $age < self::RETRY,
				'outside' === $method       => ( $stored['root'] ?? '' ) === self::document_root(),
				'probe' === $method         => $age < self::PROBE_LIFE,
				default                     => false,
			};
			if ( $fresh ) {
				return null === $stored['private'] ? null : (bool) $stored['private'];
			}
		}
		return self::recheck();
	}

	/**
	 * Creates the folder if needed and checks again whether it is private.
	 */
	public static function recheck(): ?bool {
		$path   = self::path();
		$result = self::check( $path );
		update_site_option(
			self::OPTION,
			array(
				'path'    => $path,
				'private' => $result['private'],
				'method'  => $result['method'],
				'reason'  => $result['reason'],
				'root'    => self::document_root(),
				'checked' => time(),
			)
		);
		return $result['private'];
	}
	/**
	 * Whether files can be written there right now (exists, writable, private).
	 */
	public static function ready(): bool {
		return true === self::is_private() && is_dir( self::path() ) && wp_is_writable( self::path() );
	}

	/**
	 * Explanation for admin screens when the folder is not ready.
	 */
	public static function problem(): string {
		$path = self::path();
		if ( ! is_dir( $path ) ) {
			/* translators: %s: folder path. */
			return sprintf( __( 'The private folder %s does not exist and could not be created. Create it (writable by the web server), or set SENTINEL_SHIELD_DATA_DIR in wp-config.php to a folder outside the web root.', 'sentinel-shield' ), $path );
		}
		if ( ! wp_is_writable( $path ) ) {
			/* translators: %s: folder path. */
			return sprintf( __( 'The private folder %s is not writable by the web server.', 'sentinel-shield' ), $path );
		}
		$private = self::is_private();
		if ( false === $private ) {
			/* translators: %s: folder path. */
			return sprintf( __( 'The folder %s can be downloaded over the web, so nothing sensitive is written there. Set SENTINEL_SHIELD_DATA_DIR in wp-config.php to a folder outside the web root.', 'sentinel-shield' ), $path );
		}
		if ( null === $private ) {
			$stored = get_site_option( self::OPTION );
			$reason = is_array( $stored ) ? (string) ( $stored['reason'] ?? '' ) : '';
			/* translators: 1: folder path, 2: why it could not be confirmed. */
			return sprintf( __( 'Could not confirm that %1$s cannot be downloaded over the web (%2$s). Set SENTINEL_SHIELD_DATA_DIR in wp-config.php to a folder outside the web root, or use Re-check once the cause is fixed.', 'sentinel-shield' ), $path, '' !== $reason ? $reason : __( 'unknown reason', 'sentinel-shield' ) );
		}
		return '';
	}

	/**
	 * Checks a folder.
	 *
	 * @param string $path Folder.
	 * @return array{private:?bool, method:string, reason:string}
	 */
	private static function check( string $path ): array {
		$unknown = static fn( string $reason ): array => array(
			'private' => null,
			'method'  => '',
			'reason'  => $reason,
		);
		if ( ! is_dir( $path ) && ! wp_mkdir_p( $path ) ) {
			return $unknown( __( 'the folder could not be created', 'sentinel-shield' ) );
		}
		$real = realpath( $path );
		$root = self::document_root();
		$base = '' === $root ? false : realpath( $root );
		if ( false === $real ) {
			return $unknown( __( 'the folder could not be resolved', 'sentinel-shield' ) );
		}
		if ( false === $base ) {
			return $unknown( __( 'the web server\'s document root is not known yet; open any admin page in a browser, then re-check', 'sentinel-shield' ) );
		}
		$real = trailingslashit( wp_normalize_path( $real ) );
		$base = trailingslashit( wp_normalize_path( $base ) );
		if ( ! str_starts_with( $real, $base ) ) {
			return array(
				'private' => true,
				'method'  => 'outside',
				'reason'  => '',
			);
		}
		// Inside the document root: its URL follows from the document root.
		$origin = self::origin();
		if ( '' === $origin ) {
			return $unknown( __( 'the site\'s address could not be worked out', 'sentinel-shield' ) );
		}
		return self::probe( $path, $origin . '/' . ltrim( substr( $real, strlen( $base ) ), '/' ) );
	}

	/**
	 * Places a test file in the folder and a control file in uploads, and
	 * fetches both. Private only when the control file is served and the test
	 * file is refused; public when the test file is served; unknown otherwise.
	 *
	 * @param string $path Folder.
	 * @param string $url  The folder's URL (trailing slash).
	 * @return array{private:?bool, method:string, reason:string}
	 */
	private static function probe( string $path, string $url ): array {
		$result  = static fn( ?bool $verdict, string $reason = '' ): array => array(
			'private' => $verdict,
			'method'  => true === $verdict ? 'probe' : '',
			'reason'  => $reason,
		);
		$uploads = wp_upload_dir( null, false );
		if ( ! empty( $uploads['error'] ) || ! wp_mkdir_p( $uploads['basedir'] ) ) {
			return $result( null, __( 'no uploads folder to compare with', 'sentinel-shield' ) );
		}
		$name    = 'ss-probe-' . wp_generate_password( 12, false ) . '.txt';
		$token   = wp_generate_password( 24, false );
		$files   = array( $path . '/' . $name, $uploads['basedir'] . '/' . $name );
		$written = true;
		foreach ( $files as $file ) {
			$written = $written && false !== @file_put_contents( $file, $token ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Short-lived test file.
		}
		$fetch   = static function ( string $target ) use ( $token ): string {
			$response = wp_remote_get(
				$target,
				array(
					'timeout'     => 5,
					'redirection' => 0,
				)
			);
			if ( is_wp_error( $response ) ) {
				return 'error';
			}
			$code = (int) wp_remote_retrieve_response_code( $response );
			if ( 200 === $code ) {
				return str_contains( (string) wp_remote_retrieve_body( $response ), $token ) ? 'served' : 'other';
			}
			return in_array( $code, array( 403, 404, 410 ), true ) ? 'refused' : 'other';
		};
		$control = $written ? $fetch( trailingslashit( $uploads['baseurl'] ) . $name ) : 'error';
		$test    = $written ? $fetch( trailingslashit( $url ) . $name ) : 'error';
		foreach ( $files as $file ) {
			if ( is_file( $file ) ) {
				wp_delete_file( $file );
			}
		}
		if ( ! $written ) {
			return $result( null, __( 'the test files could not be written', 'sentinel-shield' ) );
		}
		if ( 'served' === $test ) {
			return $result( false );
		}
		if ( 'served' !== $control ) {
			return $result( null, __( 'the site could not fetch its own test file from uploads, so a refusal would prove nothing', 'sentinel-shield' ) );
		}
		if ( 'refused' !== $test ) {
			return $result( null, __( 'the test file got an unexpected answer', 'sentinel-shield' ) );
		}
		return $result( true );
	}

	/**
	 * The site's scheme, host and port, from the WordPress address.
	 */
	private static function origin(): string {
		$parts = wp_parse_url( site_url() );
		if ( ! is_array( $parts ) || empty( $parts['host'] ) ) {
			return '';
		}
		return ( $parts['scheme'] ?? 'https' ) . '://' . $parts['host'] . ( isset( $parts['port'] ) ? ':' . $parts['port'] : '' );
	}

	/**
	 * DOCUMENT_ROOT of this request ('' on the command line).
	 */
	private static function server_root(): string {
		return untrailingslashit( wp_normalize_path( (string) ( $_SERVER['DOCUMENT_ROOT'] ?? '' ) ) ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- Only compared as a path.
	}
}
