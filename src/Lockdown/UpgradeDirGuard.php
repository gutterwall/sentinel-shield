<?php
/**
 * Keeps wp-content/upgrade/ off the web.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Lockdown;

defined( 'ABSPATH' ) || exit;

/**
 * WordPress unpacks every update in wp-content/upgrade/. No visitor ever needs
 * to reach it, and during a core update it holds a runnable copy of the
 * installer (CVE-2026-119977). Those requests run the installer's own files
 * and never load WordPress, so no plugin firewall sees them: only the web
 * server can refuse them.
 *
 * On Apache and LiteSpeed a marked block in wp-content/.htaccess refuses the
 * folder. It must not live inside the folder: older WordPress empties
 * wp-content/upgrade/ before unpacking, which would delete it. nginx ignores
 * .htaccess, so its rule is shown to the administrator instead.
 */
final class UpgradeDirGuard {

	public const MARKER = 'Sentinel Shield upgrade folder';

	/**
	 * URL path of the content folder, without the trailing slash (/wp-content).
	 */
	public static function content_path(): string {
		return untrailingslashit( (string) wp_parse_url( content_url(), PHP_URL_PATH ) );
	}

	/**
	 * Apache rules that refuse the folder.
	 *
	 * @return list<string>
	 */
	public static function htaccess_lines(): array {
		$pattern = '^' . preg_quote( self::content_path(), '#' ) . '/upgrade(?:/|$)';
		return array(
			'# Refuses web requests into wp-content/upgrade/, where WordPress unpacks updates (CVE-2026-119977).',
			'<IfModule mod_alias.c>',
			'	RedirectMatch 403 ' . $pattern,
			'</IfModule>',
			'<IfModule !mod_alias.c>',
			'	<IfModule mod_authz_core.c>',
			'		<If "%{REQUEST_URI} =~ m#' . $pattern . '#">',
			'			Require all denied',
			'		</If>',
			'	</IfModule>',
			'</IfModule>',
		);
	}

	/**
	 * Equivalent rule for nginx (server block).
	 */
	public static function nginx_rule(): string {
		return 'location ^~ ' . self::content_path() . '/upgrade/ { deny all; }';
	}

	/**
	 * Path of wp-content/.htaccess.
	 */
	public static function htaccess_path(): string {
		return trailingslashit( WP_CONTENT_DIR ) . '.htaccess';
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
	 * @param bool $enabled Whether the folder should be refused.
	 */
	public static function sync_htaccess( bool $enabled ): bool {
		$path = self::htaccess_path();
		if ( $enabled ) {
			if ( ! is_dir( WP_CONTENT_DIR ) ) {
				return false;
			}
			require_once ABSPATH . 'wp-admin/includes/misc.php';
			return insert_with_markers( $path, self::MARKER, self::htaccess_lines() );
		}
		if ( ! is_file( $path ) || ! is_writable( $path ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable -- Plain check before a local write.
			return true;
		}
		$content = (string) file_get_contents( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file.
		$cleaned = preg_replace( '/\n?# BEGIN ' . preg_quote( self::MARKER, '/' ) . '\n.*?# END ' . preg_quote( self::MARKER, '/' ) . '\n?/s', "\n", $content );
		if ( null === $cleaned || $cleaned === $content ) {
			return true;
		}
		if ( '' === trim( $cleaned ) ) {
			return wp_delete_file_from_directory( $path, WP_CONTENT_DIR );
		}
		// insert_with_markers() leaves a blank line where the block was; take it back out.
		return false !== file_put_contents( $path, trim( $cleaned, "\n" ) . "\n" ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Local file, same as insert_with_markers().
	}

	/**
	 * Asks the site itself for the folder and reports what came back: 'refused'
	 * (403, or 404 for a folder that exists), 'open' (a 2xx or 3xx answer, which
	 * means the folder is served or listed) or 'unknown' (no folder, a failed
	 * request as loopback requests are on some hosts, or a server error).
	 */
	public static function probe(): string {
		$dir = trailingslashit( WP_CONTENT_DIR ) . 'upgrade';
		if ( ! is_dir( $dir ) ) {
			return 'unknown'; // Nothing to reach, and nothing to compare a 404 with.
		}
		$response = wp_remote_get(
			content_url( 'upgrade/' ),
			array(
				'timeout'     => 5,
				'redirection' => 0,
				'sslverify'   => false,
				'headers'     => array( 'Cache-Control' => 'no-cache' ),
			)
		);
		if ( is_wp_error( $response ) ) {
			return 'unknown';
		}
		$code = (int) wp_remote_retrieve_response_code( $response );
		if ( 403 === $code || 404 === $code ) {
			return 'refused';
		}
		return $code >= 500 || 0 === $code ? 'unknown' : 'open';
	}
}
