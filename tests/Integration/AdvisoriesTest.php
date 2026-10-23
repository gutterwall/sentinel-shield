<?php
/**
 * October 2026 incidents: Rank Math PRO backdoor, UpdraftCentral key theft, PHP2Shell.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Tests\Integration;

use SentinelShield\Firewall\Gate;
use SentinelShield\Firewall\RuleCache;
use SentinelShield\Lockdown\AdminRegistry;
use SentinelShield\Lockdown\Advisories;
use SentinelShield\Lockdown\Hardening;
use SentinelShield\Lockdown\IntegrityScanner;
use SentinelShield\Lockdown\RequestGuard;
use SentinelShield\Net\Cidr;
use SentinelShield\Plugin;
use SentinelShield\Repository\BlockRepository;
use SentinelShield\Repository\EventRepository;
use SentinelShield\Safety\Health;
use SentinelShield\Settings;

/**
 * Markers are assembled from parts so this file does not look like the malware to other scanners.
 */
final class AdvisoriesTest extends \WP_UnitTestCase {

	use AdminUsers;

	/**
	 * Files and folders created by a test.
	 *
	 * @var list<string>
	 */
	private array $created = array();

	/**
	 * Hardening instance under test.
	 *
	 * @var Hardening|null
	 */
	private ?Hardening $hardening = null;

	private const XOR_KEY = 'xmm' . 'qhn';
	private const CNC     = 'rank1' . 'cdn.com';

	public function set_up(): void {
		parent::set_up();
		delete_site_option( IntegrityScanner::REPORT_OPTION );
		delete_site_option( IntegrityScanner::BASELINE_OPTION );
		delete_site_option( IntegrityScanner::UPLOADS_STATE );
		global $wpdb;
		$wpdb->query( $wpdb->prepare( 'DELETE FROM %i', $this->events()->table() ) );
		$wpdb->query( $wpdb->prepare( 'DELETE FROM %i', Plugin::instance()->container()->get( BlockRepository::class )->table() ) );
		Plugin::instance()->container()->get( RuleCache::class )->flush();
		reset_phpmailer_instance();
	}

	public function tear_down(): void {
		if ( null !== $this->hardening ) {
			remove_filter( 'pre_http_request', array( $this->hardening, 'filter_http' ), 0 );
			remove_action( 'upgrader_process_complete', array( $this->hardening, 'on_upgrader' ) );
			remove_action( 'activated_plugin', array( $this->hardening, 'on_activated' ) );
			remove_action( 'update_user_meta', array( $this->hardening, 'before_caps_change' ) );
			remove_action( 'updated_user_meta', array( $this->hardening, 'after_caps_change' ) );
			remove_action( 'added_user_meta', array( $this->hardening, 'after_caps_change' ) );
			remove_action( 'granted_super_admin', array( $this->hardening, 'on_super_admin' ) );
		}
		foreach ( array_reverse( $this->created ) as $path ) {
			if ( is_dir( $path ) ) {
				@rmdir( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Shared folders may not be empty.
			} elseif ( is_file( $path ) ) {
				wp_delete_file( $path );
			}
		}
		$this->created = array();
		wp_clean_plugins_cache( false );
		delete_site_option( 'updraft_central_localkeys' );
		delete_site_option( Settings::OPTION );
		Plugin::instance()->container()->get( Settings::class )->refresh();
		unset( $_POST['udrpc_message'] );
		parent::tear_down();
	}

	private function events(): EventRepository {
		return Plugin::instance()->container()->get( EventRepository::class );
	}

	/**
	 * Writes a file (creating folders) and remembers it for cleanup.
	 */
	private function put( string $path, string $content ): string {
		$missing = array();
		for ( $dir = dirname( $path ); ! is_dir( $dir ); $dir = dirname( $dir ) ) {
			$missing[] = $dir;
		}
		foreach ( array_reverse( $missing ) as $dir ) {
			mkdir( $dir );
			$this->created[] = $dir;
		}
		file_put_contents( $path, $content );
		$this->created[] = $path;
		return $path;
	}

	/**
	 * A plugin main file with a header.
	 */
	private function plugin( string $slug, string $name, string $version, string $body = '' ): string {
		$path = $this->put( WP_PLUGIN_DIR . "/$slug/$slug.php", "<?php\n/*\nPlugin Name: $name\nVersion: $version\n*/\n$body\n" );
		wp_clean_plugins_cache( false );
		return $path;
	}

	/**
	 * Incident findings of a fresh scan.
	 *
	 * @return list<array<string, mixed>>
	 */
	private function scan(): array {
		$c      = Plugin::instance()->container();
		$report = ( new IntegrityScanner( new AdminRegistry(), $c->get( EventRepository::class ), $c->get( Settings::class ) ) )->run( true );
		return array_values( array_filter( $report['findings'], static fn( array $f ): bool => 'advisories' === $f['check'] ) );
	}

	/**
	 * The one finding whose title contains $needle.
	 *
	 * @param list<array<string, mixed>> $findings Findings.
	 * @return array<string, mixed>
	 */
	private static function find( array $findings, string $needle ): array {
		$hits = array_values( array_filter( $findings, static fn( array $f ): bool => str_contains( (string) $f['title'], $needle ) ) );
		self::assertCount( 1, $hits, "One finding titled '$needle' in: " . implode( ' | ', array_column( $findings, 'title' ) ) );
		return $hits[0];
	}

	private function harden( array $lockdown ): Hardening {
		update_site_option( Settings::OPTION, array( 'lockdown' => $lockdown ) );
		$c        = Plugin::instance()->container();
		$settings = $c->get( Settings::class );
		$settings->refresh();
		$this->hardening = new Hardening( $settings, new AdminRegistry(), $c->get( EventRepository::class ), static fn(): string => '203.0.113.9' );
		$this->hardening->register();
		return $this->hardening;
	}

	private function guard( array $lockdown, ?\Closure $respond = null ): RequestGuard {
		update_site_option( Settings::OPTION, array( 'lockdown' => $lockdown ) );
		$c        = Plugin::instance()->container();
		$settings = $c->get( Settings::class );
		$settings->refresh();
		return new RequestGuard( $settings, $c->get( EventRepository::class ), static fn(): bool => false, $c->get( Gate::class ), static fn(): string => '43.250.53.42', $respond );
	}

	public function test_php_versions(): void {
		$this->assertSame( 'vulnerable', Advisories::php_status( '8.3.6' )['state'] );
		$this->assertSame( '8.3.36', Advisories::php_status( '8.3.6' )['fixed'] );
		$this->assertSame( 'fixed', Advisories::php_status( '8.3.36' )['state'] );
		$this->assertSame( 'fixed', Advisories::php_status( '8.4.30' )['state'] );
		$this->assertSame( 'vulnerable', Advisories::php_status( '8.5.11' )['state'] );
		$this->assertSame( 'fixed', Advisories::php_status( '8.6.0' )['state'], 'Branches after the fix.' );
		$this->assertSame( 'fixed', Advisories::php_status( '9.0.0' )['state'] );
		$this->assertSame( 'unknown', Advisories::php_status( '8.1.30' )['state'], 'No upstream fix for 8.1: depends on the vendor.' );
		$this->assertSame( 'unknown', Advisories::php_status( '8.3.6-1+deb12u1', '-1+deb12u1' )['state'], 'Distribution builds keep their old number.' );
		$this->assertSame( 'vulnerable', Advisories::php_status( '8.1.2-1ubuntu2.27', '-1ubuntu2.27' )['state'] );
		$this->assertSame( 'fixed', Advisories::php_status( '8.1.2-1ubuntu2.28', '-1ubuntu2.28' )['state'] );
		$this->assertSame( 'fixed', Advisories::php_status( '8.1.2', '-1ubuntu2.31' )['state'] );
		$this->assertSame( 'unknown', Advisories::php_status( 'garbage' )['state'] );
		$this->assertSame( 'unknown', Advisories::php_status( '8.3.6', '', true )['state'], 'Ubuntu 24.04 reports plain 8.3.6 whatever the package revision.' );
		$this->assertSame( 'fixed', Advisories::php_status( '8.3.36', '', true )['state'] );
		$this->assertTrue( Advisories::is_distribution_build( '/etc/php/8.3/fpm/php.ini' ) );
		$this->assertTrue( Advisories::is_distribution_build( '/etc/php.ini' ) );
		$this->assertTrue( Advisories::is_distribution_build( '/opt/cpanel/ea-php83/root/etc/php.ini' ) );
		$this->assertTrue( Advisories::is_distribution_build( '/opt/alt/php83/etc/php.ini' ) );
		$this->assertFalse( Advisories::is_distribution_build( '/usr/local/etc/php/php.ini' ), 'Official Docker images are upstream builds.' );
		$this->assertFalse( Advisories::is_distribution_build( '' ) );

		$ini = static fn( array $values ): \Closure => static fn( string $k ): string => $values[ $k ] ?? '';
		$this->assertSame( array( 'session.upload_progress.enabled=0' ), Advisories::php_stopgaps( $ini( array( 'session.upload_progress.enabled' => '1' ) ), '8.3.6' ) );
		$this->assertSame( array(), Advisories::php_stopgaps( $ini( array( 'session.upload_progress.enabled' => '0' ) ), '8.3.6' ) );
		$this->assertSame( array( 'fatal_error_backtraces=0' ), Advisories::php_stopgaps( $ini( array( 'fatal_error_backtraces' => 'On' ) ), '8.5.1' ) );
		$this->assertSame( array(), Advisories::php_stopgaps( $ini( array( 'fatal_error_backtraces' => 'On' ) ), '8.4.1' ), 'Only 8.5 has the setting.' );
	}

	public function test_request_and_address_markers(): void {
		$this->assertNotNull( Advisories::request_match( array( '_9f' . '5696' => 'a' ), array() ) );
		$this->assertNotNull( Advisories::request_match( array( '_9f' . '5696' => '' ), array() ), 'Presence is enough.' );
		$this->assertNull( Advisories::request_match( array( 'p' => '1' ), array( 'PHPSESSID' => 'abc,DEF-123' ) ) );
		$this->assertNotNull( Advisories::request_match( array(), array( 'PHPSESSID' => str_repeat( 'a', 257 ) ) ) );
		$this->assertNull( Advisories::request_match( array(), array( 'PHPSESSID' => str_repeat( 'a', 256 ) ) ) );
		$this->assertNotNull( Advisories::request_match( array(), array( 'PHPSESSID' => "abc\x00def" ) ) );
		$this->assertNotNull( Advisories::request_match( array(), array( 'PHPSESSID' => array( 'x' ) ) ) );

		$this->assertTrue( Advisories::is_attack_ip( '43.250.53.42' ) );
		$this->assertTrue( Advisories::is_attack_ip( '2a09:bac5:4e21:2e3c:0:0:49b:9' ), 'Any spelling of the IPv6 address.' );
		$this->assertFalse( Advisories::is_attack_ip( '43.250.53.43' ) );
		$this->assertFalse( Advisories::is_attack_ip( 'not an ip' ) );

		$this->assertSame( 'malware host ' . self::CNC, Advisories::outbound_match( 'https://' . self::CNC . '/x.js' ) );
		$this->assertSame( 'malware host ' . self::CNC, Advisories::outbound_match( 'https://API.' . strtoupper( self::CNC ) . './v1' ) );
		$this->assertNull( Advisories::outbound_match( 'https://' . self::CNC . '.example.net/' ) );
		$this->assertNull( Advisories::outbound_match( 'https://notrank1cdn.com/' ) );
		$this->assertNull( Advisories::outbound_match( 'not a url' ) );

		$this->assertTrue( Advisories::updraft_forgeable( '1.26.4' ) );
		$this->assertFalse( Advisories::updraft_forgeable( '1.26.5' ) );
		$this->assertTrue( Advisories::updraft_forgeable( '2.25.0' ) );
		$this->assertTrue( Advisories::updraft_outdated( '1.26.12' ) );
		$this->assertFalse( Advisories::updraft_outdated( '1.26.13' ) );
		$this->assertTrue( Advisories::updraft_outdated( '2.26.12.1' ) );
		$this->assertFalse( Advisories::updraft_outdated( '2.26.13' ) );
		$this->assertFalse( Advisories::updraft_outdated( '3.0.0' ), 'Unknown major versions are not judged.' );
		$this->assertCount( 3, Advisories::incidents() );
	}

	public function test_signatures_include_incident_markers(): void {
		$sev = static fn( string $code ): string => IntegrityScanner::worst( IntegrityScanner::signatures( $code ), 'ok' );
		$this->assertSame( 'critical', $sev( '<?php $k = "' . self::XOR_KEY . '";' ) );
		$this->assertSame( 'critical', $sev( '<?php wp_remote_get( "https://' . self::CNC . '/c" );' ) );
		$this->assertSame( 'critical', $sev( "* * * * * php /tmp/x.php #ms6" . "v46" ) );
		$this->assertSame( 'critical', $sev( '<?php if ( isset( $_GET[\'_9f' . '5696\'] ) ) {}' ) );
		$this->assertSame( 'critical', $sev( "/*\nDescription: Small maintenance toolkit: " . "keeps option storage tidy.\n*/" ) );
		$this->assertSame( 'warning', $sev( '<?php $p = proc_open( $cmd, $d, $pipes );' ) );
		$this->assertSame( 'warning', $sev( '<?php $d = base64_decode( $b ); for ( $i = 0; $i < 9; $i++ ) { $o .= chr( ord( $d[ $i ] ) ^ ord( $k[ $i % 6 ] ) ); }' ) );
		$this->assertSame( 'ok', $sev( "<?php\n// Redis object cache drop-in.\nfunction wp_cache_get( \$k ) { return false; }" ) );
		$this->assertSame( 'ok', $sev( '<?php $x = base64_decode( $y ); $z = $a ^ $b;' ), 'XOR alone next to base64 is not enough.' );
	}

	public function test_rank_math_pro_traces(): void {
		global $wpdb;
		$main = $this->plugin( 'seo-by-rank-math-pro', 'Rank Math SEO PRO', '3.0.123' );
		rename( $main, dirname( $main ) . '/rank-math-pro.php' );
		$this->created[] = dirname( $main ) . '/rank-math-pro.php';
		$main            = dirname( $main ) . '/rank-math-pro.php';
		wp_clean_plugins_cache( false );
		touch( $main, Advisories::RANKMATH_WINDOW[0] - DAY_IN_SECONDS );
		$found = self::find( $this->scan(), 'Rank Math PRO 3.0.123 is installed' );
		$this->assertSame( 'warning', $found['severity'], 'A copy written before the window is probably clean.' );
		$this->assertStringContainsString( 'probably clean', $found['detail'] );

		touch( $main, Advisories::RANKMATH_WINDOW[0] + 600 );
		foreach ( Advisories::RANKMATH_OPTIONS as $option ) {
			add_option( $option, 'x', '', false );
		}
		$uploads = wp_get_upload_dir()['basedir'];
		$this->put( ABSPATH . WPINC . '/' . Advisories::RANKMATH_FAKE_CORE, "<?php\n// cache util\n" );
		$this->put( WP_CONTENT_DIR . '/.htaccess', "<FilesMatch \"\\.cache$\">\n  SetHandler application/x-httpd-php\n</FilesMatch>\n" );
		$this->put( $uploads . '/ss-adv/obj.cache', '<?php $k="' . self::XOR_KEY . '"; ' );
		$this->put( $uploads . '/ss-adv/page.cache', '<html>cached page</html>' );
		$this->put( WP_PLUGIN_DIR . '/ss-adv-victim/includes/helper.php', '<?php // https://' . self::CNC . '/ping' );
		$this->put( get_theme_root() . '/ss-adv-theme/inc/x.php', '<?php // ' . self::XOR_KEY );
		$this->put( get_theme_root() . '/ss-adv-theme/inc/clean.php', '<?php // clean' );

		$findings = $this->scan();
		$this->assertSame( 'critical', self::find( $findings, 'Rank Math PRO 3.0.123 is installed' )['severity'] );
		$this->assertStringContainsString( 'compromised', self::find( $findings, 'Rank Math PRO 3.0.123 is installed' )['detail'] );
		$options = self::find( $findings, 'Options written by the Rank Math PRO backdoor' );
		$this->assertSame( 'critical', $options['severity'] );
		foreach ( Advisories::RANKMATH_OPTIONS as $option ) {
			$this->assertStringContainsString( $option, $options['title'] );
		}
		$this->assertSame( 'critical', self::find( $findings, Advisories::RANKMATH_FAKE_CORE )['severity'] );
		$this->assertSame( 'critical', self::find( $findings, 'makes .cache files run as PHP' )['severity'] );
		$this->assertSame( 'critical', self::find( $findings, 'obj.cache' )['severity'] );
		$this->assertSame( array(), array_filter( $findings, static fn( array $f ): bool => str_contains( (string) $f['title'], 'page.cache' ) ), 'A cache file without PHP is fine.' );
		$this->assertSame( 'critical', self::find( $findings, 'ss-adv-victim/includes/helper.php' )['severity'], 'The deep search covers other plugins.' );
		$this->assertSame( 'critical', self::find( $findings, 'ss-adv-theme/inc/x.php' )['severity'], 'And themes.' );
		$this->assertSame( array(), array_filter( $findings, static fn( array $f ): bool => str_contains( (string) $f['title'], 'sentinel-shield/src' ) ), 'Never its own marker list.' );
		$this->assertSame( array(), array_filter( $findings, static fn( array $f ): bool => str_contains( (string) $f['title'], 'clean.php' ) ) );

		foreach ( Advisories::RANKMATH_OPTIONS as $option ) {
			delete_option( $option );
		}
		unset( $wpdb );
	}

	public function test_deep_search_only_runs_with_traces(): void {
		$this->put( WP_PLUGIN_DIR . '/ss-adv-victim/includes/helper.php', '<?php // https://' . self::CNC . '/ping' );
		$findings = $this->scan();
		$this->assertSame( array(), array_filter( $findings, static fn( array $f ): bool => str_contains( (string) $f['title'], 'helper.php' ) ), 'No traces elsewhere: plugin folders are not walked twice a day.' );
	}

	public function test_updraftcentral_backdoor_plugins_and_keys(): void {
		$this->plugin( 'ss-speed-desk', 'Speed Desk', '1.0', '// Small maintenance toolkit: ' . "keeps option storage tidy.\nif ( isset( \$_GET['_9f" . "5696'] ) ) {}" );
		$this->plugin( 'ss-nav-hub', 'Nav Hub', '1.0' );
		$this->plugin( 'ss-honest', 'Honest Plugin', '1.0' );
		$updraft = $this->put( WP_PLUGIN_DIR . '/updraftplus/updraftplus.php', "<?php\n/*\nPlugin Name: UpdraftPlus - Backup/Restore\nVersion: 1.26.4\n*/\n" );
		wp_clean_plugins_cache( false );

		$findings = $this->scan();
		$desk     = self::find( $findings, 'Speed Desk' );
		$this->assertSame( 'critical', $desk['severity'] );
		$this->assertStringContainsString( 'trigger parameter', $desk['detail'] );
		$hub = self::find( $findings, 'Nav Hub' );
		$this->assertSame( 'warning', $hub['severity'], 'A name alone is only a warning: it can be approved.' );
		$this->assertSame( array(), array_filter( $findings, static fn( array $f ): bool => str_contains( (string) $f['title'], 'Honest Plugin' ) ) );
		$this->assertSame( 'critical', self::find( $findings, 'UpdraftPlus 1.26.4' )['severity'], 'Forged unsigned commands.' );

		$this->assertNotNull( IntegrityScanner::approve( $hub['id'], 1 ) );
		$this->assertSame( 'ok', self::find( $this->scan(), 'Nav Hub' )['severity'] );

		file_put_contents( $updraft, "<?php\n/*\nPlugin Name: UpdraftPlus - Backup/Restore\nVersion: 1.26.12\n*/\n" );
		wp_clean_plugins_cache( false );
		$this->assertSame( array(), array_filter( $this->scan(), static fn( array $f ): bool => str_contains( (string) $f['title'], 'UpdraftPlus' ) && 'notice' !== $f['severity'] ), 'Outdated, but no keys: only a notice.' );

		update_site_option(
			'updraft_central_localkeys',
			array(
				'k1' => array(
					'name'    => 'UpdraftCentral cloud',
					'created' => Advisories::UPDRAFT_CUTOFF - DAY_IN_SECONDS,
				),
			)
		);
		$this->assertSame( 'critical', self::find( $this->scan(), 'UpdraftPlus 1.26.12' )['severity'] );

		file_put_contents( $updraft, "<?php\n/*\nPlugin Name: UpdraftPlus - Backup/Restore\nVersion: 1.26.13\n*/\n" );
		wp_clean_plugins_cache( false );
		$updated = self::find( $this->scan(), 'UpdraftPlus 1.26.13' );
		$this->assertSame( 'warning', $updated['severity'], 'Updated, but keys from before the theft are still stored.' );

		update_site_option(
			'updraft_central_localkeys',
			array(
				'k2' => array(
					'name'    => 'Reconnected',
					'created' => Advisories::UPDRAFT_CUTOFF + DAY_IN_SECONDS,
				),
			)
		);
		$this->assertSame( array(), array_filter( $this->scan(), static fn( array $f ): bool => str_contains( (string) $f['title'], 'UpdraftPlus' ) ), 'Updated and reconnected: nothing to report.' );
	}

	public function test_backdoor_accounts(): void {
		$ioc     = self::factory()->user->create( array( 'user_login' => 'web.tech988', 'role' => 'editor' ) );
		$support = self::factory()->user->create( array( 'user_login' => 'wpsupport_7f3a', 'role' => 'administrator' ) );
		$mail    = self::factory()->user->create( array( 'user_login' => 'helpdesk', 'user_email' => 'ops@wp-mail.net' ) );
		$fake    = self::factory()->user->create( array( 'user_login' => 'system_staff', 'user_email' => 'staff@example.com', 'role' => 'administrator' ) );
		$normal  = self::factory()->user->create( array( 'user_login' => 'wpsupporter', 'role' => 'administrator' ) );
		if ( is_multisite() ) {
			grant_super_admin( $fake ); // Network administrators are the privileged accounts there.
		}

		$findings = $this->scan();
		foreach ( array( $ioc, $support, $mail ) as $id ) {
			$this->assertSame( 'critical', self::find( $findings, '(ID ' . $id . ',' )['severity'] );
		}
		$this->assertSame( 'warning', self::find( $findings, 'system_staff (ID ' . $fake . ')' )['severity'] );
		$this->assertSame( array(), array_filter( $findings, static fn( array $f ): bool => str_contains( (string) $f['title'], '(ID ' . $normal . ',' ) ), 'LIKE wildcards are escaped: wpsupporter is not wpsupport_.' );
	}

	public function test_php_finding_matches_the_running_php(): void {
		$state    = Advisories::php_status_now()['state'];
		$findings = array_values( array_filter( $this->scan(), static fn( array $f ): bool => str_contains( (string) $f['title'], 'PHP2Shell' ) ) );
		if ( 'fixed' === $state ) {
			$this->assertSame( array(), $findings );
		} else {
			$this->assertCount( 1, $findings );
			$this->assertSame( 'vulnerable' === $state ? 'critical' : 'warning', $findings[0]['severity'] );
			$this->assertStringContainsString( PHP_SAPI, $findings[0]['detail'] );
			$this->assertNotNull( IntegrityScanner::approve( $findings[0]['id'], 1 ), 'A host-confirmed backport can be approved.' );
		}
		$rows = array_column( ( new Health( Plugin::instance()->container() ) )->checks(), null, 'id' );
		$this->assertSame( 'fixed' === $state ? 'ok' : 'warn', $rows['php']['state'] );
	}

	public function test_request_guard(): void {
		$refused = array();
		$guard   = $this->guard( array(), static function ( string $why ) use ( &$refused ): void {
			$refused[] = $why;
		} );
		$this->assertNotNull( $guard->decide( array( '_9f' . '5696' => 'x' ), array(), array(), '198.51.100.1' ) );
		$this->assertNotNull( $guard->decide( array(), array(), array( 'PHPSESSID' => str_repeat( 'Z', 400 ) ), '198.51.100.1' ) );
		$this->assertNotNull( $guard->decide( array(), array(), array(), '43.250.53.42' ) );
		$this->assertNull( $guard->decide( array( 'p' => '1' ), array( 'udrpc_message' => 'x' ), array(), '198.51.100.1' ), 'UpdraftCentral is allowed unless refused by setting.' );

		$guard->enforce();
		$this->assertSame( array( 'address used by the UpdraftCentral backdoor campaign' ), $refused );
		$guard->enforce();
		$this->assertSame( 1, $this->events()->count_since( array( 'lockdown_request' ), time() - 60 ), 'Logged once a minute per address and reason.' );

		Plugin::instance()->container()->get( BlockRepository::class )->add( 'allow', Cidr::parse( '43.250.53.42' ), 'shared VPN exit', 'manual' );
		Plugin::instance()->container()->get( RuleCache::class )->flush();
		$this->assertNull( $guard->decide( array(), array(), array(), '43.250.53.42' ), 'An allowlist entry wins for the address.' );
		$this->assertNotNull( $guard->decide( array( '_9f' . '5696' => 'x' ), array(), array(), '43.250.53.42' ), 'But not for the trigger parameter.' );

		$off = $this->guard( array( 'block_indicators' => false ) );
		$this->assertNull( $off->decide( array( '_9f' . '5696' => 'x' ), array(), array(), '198.51.100.1' ) );

		$updraft = $this->guard( array( 'block_updraftcentral' => true ) );
		$this->assertSame( 'UpdraftCentral remote command (refused by setting)', $updraft->decide( array(), array( 'udrpc_message' => 'x' ), array(), '198.51.100.1' ) );
		$this->assertNull( $updraft->decide( array(), array( 'other' => 'x' ), array(), '198.51.100.1' ) );
	}

	public function test_request_guard_is_off_for_wp_cli(): void {
		update_site_option( Settings::OPTION, array() );
		$c        = Plugin::instance()->container();
		$settings = $c->get( Settings::class );
		$settings->refresh();
		$refused = false;
		$guard   = new RequestGuard( $settings, $c->get( EventRepository::class ), static fn(): bool => true, $c->get( Gate::class ), static fn(): string => '43.250.53.42', static function () use ( &$refused ): void {
			$refused = true;
		} );
		$guard->enforce();
		$this->assertFalse( $refused );
	}

	public function test_defaults(): void {
		delete_site_option( Settings::OPTION );
		$settings = Plugin::instance()->container()->get( Settings::class );
		$settings->refresh();
		$this->assertTrue( $settings->get( 'lockdown.block_malware_hosts' ) );
		$this->assertTrue( $settings->get( 'lockdown.block_indicators' ) );
		$this->assertTrue( $settings->get( 'lockdown.alert_plugin_changes' ) );
		$this->assertFalse( $settings->get( 'lockdown.block_updraftcentral' ) );
		$this->assertFalse( $settings->get( 'lockdown.block_chain_rpc' ) );
	}

	public function test_malware_hosts_are_blocked_without_the_blockchain_setting(): void {
		$this->harden( array( 'block_malware_hosts' => true ) );
		// Stands in for the network, after Sentinel Shield had its say.
		$passed = static fn( mixed $pre ): mixed => false !== $pre ? $pre : array(
			'headers'  => array(),
			'body'     => 'passed',
			'response' => array(
				'code'    => 200,
				'message' => 'OK',
			),
			'cookies'  => array(),
		);
		add_filter( 'pre_http_request', $passed, 10 );
		$blocked = wp_remote_get( 'https://cdn.' . self::CNC . '/payload' );
		$this->assertWPError( $blocked );
		$this->assertStringContainsString( 'known to serve malware', $blocked->get_error_message() );
		$this->assertSame( 'passed', wp_remote_retrieve_body( wp_remote_post( 'https://ethereum-rpc.publicnode.com/', array( 'body' => '{"method":"eth_call"}' ) ) ), 'Blockchain gateways are a separate setting.' );
		$rows = $this->events()->query( array( 'event' => 'lockdown_outbound' ) )[0];
		$this->assertCount( 1, $rows );
		$this->assertStringContainsString( 'AdvisoriesTest.php', $rows[0]['reason'] );

		$this->hardening = null;
		remove_all_filters( 'pre_http_request' );
		$this->harden( array( 'block_malware_hosts' => false ) );
		add_filter( 'pre_http_request', $passed, 10 );
		$this->assertSame( 'passed', wp_remote_retrieve_body( wp_remote_get( 'https://cdn.' . self::CNC . '/payload' ) ), 'Off means off.' );
		remove_filter( 'pre_http_request', $passed, 10 );
	}

	public function test_plugin_changes_are_logged_and_takeovers_emailed(): void {
		$h = $this->harden( array( 'alert_plugin_changes' => true ) );
		$this->plugin( 'ss-honest', 'Honest Plugin', '1.0' );
		$this->plugin( 'ss-speed-desk', 'Speed Desk', '1.0', '// Small maintenance toolkit: ' . 'keeps option storage tidy.' );

		wp_set_current_user( self::create_admin() );
		reset_phpmailer_instance(); // The new-administrator alert.
		$h->on_activated( 'ss-honest/ss-honest.php' );
		$this->assertSame( 1, $this->events()->count_since( array( 'lockdown_plugin_change' ), time() - 60 ) );
		$this->assertFalse( tests_retrieve_phpmailer_instance()->get_sent(), 'An administrator activating a clean plugin is only logged.' );

		$_POST['udrpc_message'] = 'signed';
		$h->on_activated( 'ss-honest/ss-honest.php' );
		$sent = tests_retrieve_phpmailer_instance()->get_sent();
		$this->assertNotFalse( $sent, 'Even an administrator\'s account, when the command came through UpdraftCentral.' );
		$this->assertStringContainsString( 'the way the backdoors of 18 and 19 October 2026 were installed', $sent->body );
		unset( $_POST['udrpc_message'] );
		reset_phpmailer_instance();

		$h->on_activated( 'ss-speed-desk/ss-speed-desk.php' );
		$sent = tests_retrieve_phpmailer_instance()->get_sent();
		$this->assertStringContainsString( 'Suspicious plugin install', $sent->subject );
		$this->assertStringContainsString( 'UpdraftCentral backdoor', $sent->body );
		reset_phpmailer_instance();

		wp_set_current_user( 0 );
		$_POST['udrpc_message'] = 'signed';
		$upgrader               = new class() {
			/**
			 * Installed plugin file.
			 */
			public function plugin_info(): string {
				return 'ss-honest/ss-honest.php';
			}
		};
		$h->on_upgrader( $upgrader, array( 'type' => 'theme', 'action' => 'install' ) );
		$h->on_upgrader( $upgrader, array( 'type' => 'plugin', 'action' => 'update' ) );
		$this->assertSame( 3, $this->events()->count_since( array( 'lockdown_plugin_change' ), time() - 60 ), 'Theme installs and updates are not plugin installs.' );
		$h->on_upgrader( $upgrader, array( 'type' => 'plugin', 'action' => 'install' ) );
		$sent = tests_retrieve_phpmailer_instance()->get_sent();
		$this->assertStringContainsString( 'UpdraftCentral remote command', $sent->body );
		$this->assertStringContainsString( 'no logged-in user', $sent->body );
		$rows = $this->events()->query( array( 'event' => 'lockdown_plugin_change' ) )[0];
		$this->assertStringContainsString( 'installed', $rows[0]['reason'] );
		$this->assertSame( 'updraftcentral', Hardening::channel() );
		unset( $_POST['udrpc_message'] );
		$this->assertSame( 'web', Hardening::channel() );
	}
}
