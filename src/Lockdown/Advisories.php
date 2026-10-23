<?php
/**
 * Indicators of recently disclosed WordPress incidents.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Lockdown;

defined( 'ABSPATH' ) || exit;

/**
 * Sentinel Shield has no vulnerability database. When an incident is being
 * exploited against WordPress sites, though, the markers its attackers leave
 * (option names, file names, accounts, request parameters, hosts) are cheap to
 * look for, so the scan, the outbound filter and the request filter check
 * them. Each incident lists its sources; everything here comes from them.
 *
 * Marker strings are split in the source so other malware scanners reading
 * this file do not mistake it for the malware.
 */
final class Advisories {

	// phpcs:disable Generic.Strings.UnnecessaryStringConcat.Found -- Marker strings are split on purpose (see above).

	/**
	 * Rank Math PRO 3.0.123 builds downloaded in this window carried a backdoor (UTC).
	 */
	public const RANKMATH_WINDOW = array( 1792094520, 1792134720 ); // 15 October 2026 20:02 to 16 October 07:12.

	/**
	 * UpdraftCentral connection keys created before this time were exposed (UTC).
	 */
	public const UPDRAFT_CUTOFF = 1792357200; // 18 October 2026, 21:00 UTC (22:00 BST).

	/**
	 * UpdraftPlus releases that disconnect the exposed keys: free 1.x, Premium 2.x.
	 */
	public const UPDRAFT_FIXED = array(
		1 => '1.26.13',
		2 => '2.26.13',
	);

	/**
	 * UpdraftPlus releases that refuse forged unsigned UpdraftCentral commands (CVE-2026-10795).
	 */
	public const UPDRAFT_FORGERY_FIXED = array(
		1 => '1.26.5',
		2 => '2.26.5',
	);

	/**
	 * Distribution builds with the PHP2Shell fix backported: version prefix => first fixed build number.
	 */
	public const PHP_DISTRO_FIXED = array(
		'8.1.2-1ubuntu2.' => 28, // Ubuntu 22.04.
	);

	/**
	 * First fixed upstream release per PHP branch (CVE-2026-109618, CVE-2026-109619).
	 */
	public const PHP_FIXED = array(
		'8.2' => '8.2.35',
		'8.3' => '8.3.36',
		'8.4' => '8.4.27',
		'8.5' => '8.5.12',
	);

	/**
	 * Option names written by the Rank Math PRO backdoor.
	 */
	public const RANKMATH_OPTIONS = array( '_uf6qdn2hmm', 't8krdk990phb', '_np5pvf754c' );

	/**
	 * Fake core file planted by the Rank Math PRO backdoor (relative to wp-includes).
	 */
	public const RANKMATH_FAKE_CORE = 'class-wp-cache-util.php';

	/**
	 * Names of the backdoor plugins installed through stolen UpdraftCentral keys.
	 */
	public const UPDRAFT_PLUGIN_NAMES = array(
		'Site Health Cache',
		'Site Health 364F',
		'Asset Forge 2',
		'Content Helper',
		'Wp Forge',
		'Query Shelf',
		'Style Bridge 8F5',
		'Media Kit 183',
		'Post Dock 776',
		'Nav Hub',
		'Speed Desk',
		'Speed Kit 300',
		'Link Latch',
		'Script Shelf',
		'Feed Case',
	);

	/**
	 * Accounts created by the UpdraftCentral backdoor plugins.
	 */
	public const UPDRAFT_LOGINS = array( 'system_team850', 'web.tech988', 'cmseditor170', 'cms.tech644', 'web_mgr684', 'data-ops43' );

	/**
	 * Addresses the UpdraftCentral campaign came from.
	 */
	public const ATTACK_IPS = array( '43.250.53.42', '2a09:bac5:4e21:2e3c::49b:9' );

	/**
	 * Request parameter that makes the UpdraftCentral backdoor create its account.
	 */
	public const BACKDOOR_PARAM = '_9f' . '5696';

	/**
	 * The incidents, newest first, for the Malware Lockdown page and the docs.
	 *
	 * @return list<array{id:string, title:string, date:string, cve:string, summary:string, source:string}>
	 */
	public static function incidents(): array {
		return array(
			array(
				'id'      => 'php2shell',
				'title'   => __( 'PHP2Shell: remote code execution in PHP itself', 'sentinel-shield' ),
				'date'    => '2026-10-21',
				'cve'     => 'CVE-2026-109618, CVE-2026-109619',
				'summary' => __( 'Two flaws in PHP request handling let an unauthenticated request run code on PHP-FPM, mod_php, CGI, LiteSpeed and FrankenPHP, before WordPress loads. Fixed in PHP 8.2.35, 8.3.36, 8.4.27 and 8.5.12; older branches only through distribution backports. Exploited from 21 October. Sentinel Shield checks the PHP version and the recommended stopgap settings and logs malformed session cookies; only updating PHP fixes it.', 'sentinel-shield' ),
				'source'  => 'https://patchstack.com/articles/php-major-vulnerability-alert-10-2026/',
			),
			array(
				'id'      => 'updraftcentral',
				'title'   => __( 'Backdoor plugins installed through stolen UpdraftCentral keys', 'sentinel-shield' ),
				'date'    => '2026-10-18',
				'cve'     => '',
				'summary' => __( 'Keys stolen from TeamUpdraft were used on 18 and 19 October to send signed "install plugin" commands to sites connected to UpdraftCentral. The plugins create an account with a known password when a secret parameter is requested. UpdraftPlus 1.26.13 (Premium 2.26.13) disconnects the exposed keys.', 'sentinel-shield' ),
				'source'  => 'https://thehackernews.com/2026/10/attackers-abuse-updraftcentral-keys-to.html',
			),
			array(
				'id'      => 'rankmath-pro',
				'title'   => __( 'Rank Math PRO 3.0.123 supply-chain backdoor', 'sentinel-shield' ),
				'date'    => '2026-10-16',
				'cve'     => 'CVE-2026-111862',
				'summary' => __( 'Copies of Rank Math PRO 3.0.123 downloaded between 20:02 UTC on 15 October and 07:12 UTC on 16 October contained a self-restoring backdoor that adds administrators, PHP files, a fake core file, .htaccess rules, scheduled tasks and SSH keys. Fixed in 3.0.124, which does not remove what the backdoor already planted.', 'sentinel-shield' ),
				'source'  => 'https://thehackernews.com/2026/10/popular-wordpress-seo-plugin-rank-math.html',
			),
		);
	}

	/**
	 * Code markers: [regex, severity, reason]. Used by IntegrityScanner::signatures().
	 *
	 * @return list<array{0:string, 1:string, 2:string}>
	 */
	public static function code_markers(): array {
		return array(
			array( '/xmm' . 'qhn/', 'critical', __( 'XOR key of the Rank Math PRO backdoor (CVE-2026-111862)', 'sentinel-shield' ) ),
			array( '/rank1' . 'cdn\.com/i', 'critical', __( 'contacts rank1cdn.com, the Rank Math PRO backdoor server', 'sentinel-shield' ) ),
			array( '/#\s*ms6' . 'v46\b/', 'critical', __( 'crontab marker of the Rank Math PRO backdoor', 'sentinel-shield' ) ),
			array( '/[\'"]' . self::BACKDOOR_PARAM . '[\'"]/', 'critical', __( 'trigger parameter of the UpdraftCentral backdoor plugins', 'sentinel-shield' ) ),
			array( '/Small maintenance toolkit: ' . 'keeps option storage tidy/i', 'critical', __( 'description of the UpdraftCentral backdoor plugins', 'sentinel-shield' ) ),
			array( '/\bproc_open\s*\(/i', 'warning', __( 'starts system processes (proc_open)', 'sentinel-shield' ) ),
		);
	}

	/**
	 * Hosts known to serve malware commands; an entry matches subdomains too.
	 *
	 * @return list<string>
	 */
	public static function malware_hosts(): array {
		return array( 'rank1' . 'cdn.com' );
	}

	/**
	 * Why an outgoing request goes to a known malware host, or null.
	 *
	 * @param string $url Request URL.
	 */
	public static function outbound_match( string $url ): ?string {
		$host = strtolower( rtrim( (string) wp_parse_url( $url, PHP_URL_HOST ), '.' ) );
		if ( '' === $host ) {
			return null;
		}
		foreach ( self::malware_hosts() as $bad ) {
			if ( $host === $bad || str_ends_with( $host, '.' . $bad ) ) {
				return 'malware host ' . $bad;
			}
		}
		return null;
	}

	/**
	 * Why a request carries an attack indicator, or null.
	 *
	 * @param array<string, mixed> $get     Query parameters.
	 * @param array<string, mixed> $cookies Cookies.
	 */
	public static function request_match( array $get, array $cookies ): ?string {
		if ( array_key_exists( self::BACKDOOR_PARAM, $get ) ) {
			return 'UpdraftCentral backdoor trigger parameter';
		}
		if ( isset( $cookies['PHPSESSID'] ) ) {
			$sid = $cookies['PHPSESSID'];
			// PHP session IDs are at most 256 characters from [A-Za-z0-9,-]; PHP2Shell probes send other cookies.
			if ( ! is_string( $sid ) || strlen( $sid ) > 256 || ! preg_match( '/^[A-Za-z0-9,-]*$/', $sid ) ) {
				return 'malformed PHPSESSID cookie (PHP2Shell probe)';
			}
		}
		return null;
	}

	/**
	 * Whether an IP is one of the campaign addresses.
	 *
	 * @param string $ip IP text.
	 */
	public static function is_attack_ip( string $ip ): bool {
		$bin = @inet_pton( $ip ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Invalid input is simply not a match.
		if ( false === $bin ) {
			return false;
		}
		foreach ( self::ATTACK_IPS as $bad ) {
			if ( inet_pton( $bad ) === $bin ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * PHP2Shell exposure of a PHP build.
	 *
	 * State: fixed, vulnerable (an upstream build older than the fix), unknown
	 * (a distribution build, whose number does not show backports, or a branch
	 * with no upstream fix).
	 *
	 * @param string $version PHP_VERSION.
	 * @param string $extra   PHP_EXTRA_VERSION (distribution suffix).
	 * @param bool   $distro  Whether PHP comes from a distribution package (see is_distribution_build()).
	 * @return array{state:string, fixed:string}
	 */
	public static function php_status( string $version, string $extra = '', bool $distro = false ): array {
		if ( ! preg_match( '/^(\d+)\.(\d+)\.(\d+)/', $version, $m ) ) {
			return array(
				'state' => 'unknown',
				'fixed' => '',
			);
		}
		foreach ( self::PHP_DISTRO_FIXED as $prefix => $build ) {
			if ( str_starts_with( $version . $extra, $prefix ) || str_starts_with( $version, $prefix ) ) {
				$full = str_starts_with( $version, $prefix ) ? $version : $version . $extra;
				return array(
					'state' => (int) substr( $full, strlen( $prefix ) ) >= $build ? 'fixed' : 'vulnerable',
					'fixed' => $prefix . $build,
				);
			}
		}
		$branch = $m[1] . '.' . $m[2];
		$base   = $m[1] . '.' . $m[2] . '.' . $m[3];
		$fixed  = self::PHP_FIXED[ $branch ] ?? '';
		if ( '' !== $fixed && version_compare( $base, $fixed, '>=' ) ) {
			$state = 'fixed';
		} elseif ( version_compare( $branch, '8.5', '>' ) ) {
			$state = 'fixed'; // A branch released after the fix.
		} elseif ( '' === $fixed || '' !== $extra || $distro ) {
			$state = 'unknown';
		} else {
			$state = 'vulnerable';
		}
		return array(
			'state' => $state,
			'fixed' => $fixed,
		);
	}

	/**
	 * Whether PHP was installed from a distribution or hosting-panel package.
	 *
	 * Such packages backport security fixes without changing the version number
	 * (Ubuntu 24.04's 8.3.6 is "8.3.6" whatever its package revision), so the
	 * number cannot prove them vulnerable. Upstream builds (official Docker
	 * images, self-compiled) keep their configuration elsewhere.
	 *
	 * @param string $ini Loaded php.ini path (php_ini_loaded_file()), or its scan folder.
	 */
	public static function is_distribution_build( string $ini ): bool {
		return (bool) preg_match( '#^(?:/etc/php/\d|/etc/php\.ini$|/etc/php\.d/|/etc/opt/remi/|/opt/remi/|/opt/cpanel/ea-php|/opt/alt/php|/usr/local/lsws/lsphp|/etc/php\d)#', $ini );
	}

	/**
	 * PHP2Shell exposure of the running PHP.
	 *
	 * @return array{state:string, fixed:string}
	 */
	public static function php_status_now(): array {
		$ini = (string) php_ini_loaded_file();
		if ( '' === $ini ) {
			$ini = (string) php_ini_scanned_files();
		}
		return self::php_status( PHP_VERSION, PHP_EXTRA_VERSION, self::is_distribution_build( $ini ) );
	}

	/**
	 * Recommended stopgap PHP settings that are not in place.
	 *
	 * @param callable $ini     Reads a setting (ini_get).
	 * @param string   $version PHP version.
	 * @return list<string>
	 */
	public static function php_stopgaps( callable $ini, string $version = PHP_VERSION ): array {
		$out = array();
		if ( self::truthy( $ini( 'session.upload_progress.enabled' ) ) ) {
			$out[] = 'session.upload_progress.enabled=0';
		}
		if ( version_compare( $version, '8.5', '>=' ) && self::truthy( $ini( 'fatal_error_backtraces' ) ) ) {
			$out[] = 'fatal_error_backtraces=0';
		}
		return $out;
	}

	/**
	 * Whether an ini value means "on".
	 *
	 * @param mixed $value Value from ini_get().
	 */
	private static function truthy( mixed $value ): bool {
		return in_array( strtolower( trim( (string) $value ) ), array( '1', 'on', 'yes', 'true' ), true );
	}

	/**
	 * Whether an installed UpdraftPlus version accepts forged unsigned commands.
	 *
	 * @param string $version Plugin version.
	 */
	public static function updraft_forgeable( string $version ): bool {
		$fixed = self::UPDRAFT_FORGERY_FIXED[ (int) $version ] ?? null;
		return null !== $fixed && version_compare( $version, $fixed, '<' );
	}

	/**
	 * Whether an installed UpdraftPlus version still accepts keys issued before the cutoff.
	 *
	 * @param string $version Plugin version.
	 */
	public static function updraft_outdated( string $version ): bool {
		$major = (int) $version;
		$fixed = self::UPDRAFT_FIXED[ $major ] ?? null;
		return null !== $fixed && version_compare( $version, $fixed, '<' );
	}
	// phpcs:enable
}
