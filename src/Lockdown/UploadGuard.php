<?php
/**
 * Keeps executable code out of the uploads folder.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Lockdown;

defined( 'ABSPATH' ) || exit;

/**
 * Two layers: uploads whose name or content is PHP are rejected, and on Apache a
 * marked block in uploads/.htaccess stops any PHP file already there from running.
 * Web shells uploaded through vulnerable form or media plugins are a common way
 * in for malware such as SC.
 */
final class UploadGuard {

	public const MARKER = 'Sentinel Shield';

	/**
	 * Why a file name is dangerous, or null. Catches double extensions
	 * (shell.php.jpg) and server config files.
	 *
	 * @param string $name File name as uploaded.
	 */
	public static function dangerous_name( string $name ): ?string {
		$base = strtolower( basename( str_replace( '\\', '/', $name ) ) );
		if ( '' === $base ) {
			return null;
		}
		if ( str_starts_with( $base, '.' ) || 'php.ini' === $base ) {
			return __( 'server configuration and hidden files cannot be uploaded', 'sentinel-shield' );
		}
		if ( preg_match( '/\.(php[0-9]?|phtml|phar|phps|pht|pgif|shtml|cgi|pl|asp|aspx|jsp)(\.|$)/', $base ) ) {
			return __( 'executable script files cannot be uploaded', 'sentinel-shield' );
		}
		return null;
	}

	/**
	 * Whether a file contains PHP code (checks the first 256 KB).
	 *
	 * @param string $path Temporary file path.
	 */
	public static function contains_php( string $path ): bool {
		if ( '' === $path || ! is_readable( $path ) ) {
			return false;
		}
		$head = (string) file_get_contents( $path, false, null, 0, 262144 ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local temporary file.
		if ( false !== stripos( $head, '<?php' ) ) {
			return true;
		}
		// The short echo tag is three bytes, so only trust it in text files (no NUL bytes).
		return ! str_contains( substr( $head, 0, 8192 ), "\0" ) && str_contains( $head, '<?=' );
	}

	/**
	 * Filter for wp_handle_upload_prefilter / wp_handle_sideload_prefilter.
	 *
	 * @param array<string, mixed> $file Upload.
	 * @return array<string, mixed>
	 */
	public static function filter( array $file ): array {
		if ( ! empty( $file['error'] ) ) {
			return $file;
		}
		$reason = self::dangerous_name( (string) ( $file['name'] ?? '' ) );
		if ( null === $reason && self::contains_php( (string) ( $file['tmp_name'] ?? '' ) ) ) {
			$reason = __( 'the file contains PHP code', 'sentinel-shield' );
		}
		if ( null !== $reason ) {
			/* translators: %s: reason. */
			$file['error'] = sprintf( __( 'Upload blocked by Sentinel Shield: %s.', 'sentinel-shield' ), $reason );
			do_action( 'sentinel_shield_upload_blocked', (string) ( $file['name'] ?? '' ), $reason );
		}
		return $file;
	}

	/**
	 * Apache rules that stop PHP from running in uploads.
	 *
	 * @return list<string>
	 */
	public static function htaccess_lines(): array {
		return array(
			'# Stops PHP files in uploads from running (web shells, SC malware loaders).',
			'<FilesMatch "\.(?i:php[0-9]?|phtml|phar|phps|pht)$">',
			'	<IfModule mod_authz_core.c>',
			'		Require all denied',
			'	</IfModule>',
			'	<IfModule !mod_authz_core.c>',
			'		Order allow,deny',
			'		Deny from all',
			'	</IfModule>',
			'</FilesMatch>',
		);
	}

	/**
	 * Equivalent rule for nginx, which ignores .htaccess.
	 */
	public static function nginx_rule(): string {
		$path = wp_parse_url( (string) wp_get_upload_dir()['baseurl'], PHP_URL_PATH );
		return 'location ~* ^' . preg_quote( untrailingslashit( (string) $path ), '/' ) . '/.*\.(php[0-9]?|phtml|phar|phps|pht)$ { deny all; }';
	}

	/**
	 * Path of uploads/.htaccess.
	 */
	public static function htaccess_path(): string {
		return trailingslashit( (string) wp_get_upload_dir()['basedir'] ) . '.htaccess';
	}

	/**
	 * Whether the rules are in place.
	 */
	public static function htaccess_installed(): bool {
		$path = self::htaccess_path();
		return is_readable( $path ) && str_contains( (string) file_get_contents( $path ), '# BEGIN ' . self::MARKER ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file.
	}

	/**
	 * Adds or removes the rules.
	 *
	 * @param bool $enabled Whether PHP should be blocked.
	 */
	public static function sync_htaccess( bool $enabled ): bool {
		$path = self::htaccess_path();
		if ( $enabled ) {
			if ( ! is_dir( dirname( $path ) ) ) {
				return false;
			}
			require_once ABSPATH . 'wp-admin/includes/misc.php';
			return insert_with_markers( $path, self::MARKER, self::htaccess_lines() );
		}
		if ( ! is_file( $path ) || ! is_writable( $path ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable -- Plain check before a local write.
			return true;
		}
		$content = (string) file_get_contents( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file.
		$cleaned = preg_replace( '/\n?# BEGIN ' . preg_quote( self::MARKER, '/' ) . '.*?# END ' . preg_quote( self::MARKER, '/' ) . '\n?/s', "\n", $content );
		if ( null === $cleaned || $cleaned === $content ) {
			return true;
		}
		if ( '' === trim( $cleaned ) ) {
			return wp_delete_file_from_directory( $path, dirname( $path ) );
		}
		return false !== file_put_contents( $path, ltrim( $cleaned, "\n" ) ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Local file, same as insert_with_markers().
	}
}
