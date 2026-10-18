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
 * A folder only counts as private when it is outside DOCUMENT_ROOT, or when a
 * test file placed in it cannot be fetched over HTTP. If privacy cannot be
 * confirmed, the files are not written and the admin screens say why.
 */
final class DataDir {

	public const OPTION = 'sentinel_shield_data_dir';
	public const NAME   = 'sentinel-shield-data';

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
	 * Whether the folder is confirmed private: true, false (reachable over
	 * HTTP) or null (not confirmed). Checked once and remembered; recheck() runs
	 * the check again.
	 */
	public static function is_private(): ?bool {
		$path   = self::path();
		$stored = get_site_option( self::OPTION );
		if ( is_array( $stored ) && ( $stored['path'] ?? '' ) === $path && array_key_exists( 'private', $stored ) && is_dir( $path ) ) {
			return null === $stored['private'] ? null : (bool) $stored['private'];
		}
		return self::recheck();
	}

	/**
	 * Creates the folder if needed and checks again whether it is private.
	 */
	public static function recheck(): ?bool {
		$path    = self::path();
		$private = self::check( $path );
		update_site_option(
			self::OPTION,
			array(
				'path'    => $path,
				'private' => $private,
				'checked' => time(),
			)
		);
		return $private;
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
			/* translators: %s: folder path. */
			return sprintf( __( 'Could not confirm that %s is outside the web root (the site could not reach itself to check). Set SENTINEL_SHIELD_DATA_DIR in wp-config.php to a folder outside the web root, or use Re-check once the site can reach itself.', 'sentinel-shield' ), $path );
		}
		return '';
	}

	/**
	 * Checks a folder.
	 *
	 * @param string $path Folder.
	 */
	private static function check( string $path ): ?bool {
		if ( ! is_dir( $path ) && ! wp_mkdir_p( $path ) ) {
			return null;
		}
		if ( defined( 'SENTINEL_SHIELD_DATA_DIR' ) || has_filter( 'sentinel_shield_data_dir' ) ) {
			// Chosen by the administrator (or a test); still refuse an obviously public one.
			return self::inside_document_root( $path ) ? self::probe( $path ) : true;
		}
		$root = (string) ( $_SERVER['DOCUMENT_ROOT'] ?? '' ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- Only compared as a path.
		if ( '' !== $root && ! self::inside_document_root( $path ) ) {
			return true;
		}
		return self::probe( $path );
	}

	/**
	 * Whether a folder is inside the web server's document root (false when unknown).
	 *
	 * @param string $path Folder.
	 */
	private static function inside_document_root( string $path ): bool {
		$root = (string) ( $_SERVER['DOCUMENT_ROOT'] ?? '' ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- Only compared as a path.
		$real = realpath( $path );
		$base = '' === $root ? false : realpath( $root );
		return false !== $real && false !== $base && str_starts_with( trailingslashit( wp_normalize_path( $real ) ), trailingslashit( wp_normalize_path( $base ) ) );
	}

	/**
	 * Places a test file and tries to fetch it over HTTP: true when it cannot
	 * be fetched, false when it can, null when the site cannot reach itself.
	 *
	 * @param string $path Folder.
	 */
	private static function probe( string $path ): ?bool {
		$url = self::guess_url( $path );
		if ( '' === $url ) {
			return true; // Not under the site's folders: no URL leads there.
		}
		$name  = 'probe-' . wp_generate_password( 12, false ) . '.txt';
		$token = wp_generate_password( 24, false );
		if ( false === @file_put_contents( $path . '/' . $name, $token ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Short-lived test file.
			return null;
		}
		$response = wp_remote_get(
			$url . '/' . $name,
			array(
				'timeout'   => 5,
				'sslverify' => false,
			)
		);
		wp_delete_file( $path . '/' . $name );
		if ( is_wp_error( $response ) ) {
			return null;
		}
		return ! ( 200 === (int) wp_remote_retrieve_response_code( $response ) && str_contains( (string) wp_remote_retrieve_body( $response ), $token ) );
	}

	/**
	 * The URL a folder would have if the web server served it, or ''.
	 *
	 * @param string $path Folder.
	 */
	private static function guess_url( string $path ): string {
		$real = realpath( $path );
		$path = trailingslashit( wp_normalize_path( false === $real ? $path : $real ) );
		$root = realpath( ABSPATH );
		$abs  = trailingslashit( wp_normalize_path( false === $root ? ABSPATH : $root ) );
		$site = untrailingslashit( site_url() );
		if ( str_starts_with( $path, $abs ) ) {
			return untrailingslashit( $site . '/' . substr( $path, strlen( $abs ) ) );
		}
		// One level up: reachable only when WordPress lives in a subfolder of the web root.
		$parent = trailingslashit( dirname( untrailingslashit( $abs ) ) );
		$base   = (string) wp_parse_url( $site, PHP_URL_PATH );
		if ( str_starts_with( $path, $parent ) && '' !== trim( $base, '/' ) ) {
			$origin = substr( $site, 0, strlen( $site ) - strlen( $base ) );
			return untrailingslashit( $origin . untrailingslashit( dirname( $base ) ) . '/' . substr( $path, strlen( $parent ) ) );
		}
		return '';
	}
}
