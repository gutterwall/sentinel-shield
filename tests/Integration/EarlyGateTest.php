<?php
/**
 * Early firewall: snapshot compilation, the standalone gate running as an
 * auto_prepend_file in a real PHP server, the loader, server files and
 * Cloudflare sync.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Tests\Integration;

use SentinelShield\Firewall\CloudflareSync;
use SentinelShield\Firewall\EarlyGate;
use SentinelShield\Firewall\RuleCache;
use SentinelShield\Support\DataDir;
use SentinelShield\Net\RangeMath;
use SentinelShield\Net\IpRangeSet;
use SentinelShield\Lockdown\IntegrityScanner;
use SentinelShield\Net\Cidr;
use SentinelShield\Plugin;
use SentinelShield\Repository\BlockRepository;
use SentinelShield\Repository\EventRepository;
use SentinelShield\Settings;

final class EarlyGateTest extends \WP_UnitTestCase {

	/**
	 * PHP server process.
	 *
	 * @var resource|null
	 */
	private $server = null;

	private string $docroot = '';

	private int $port = 0;

	private string $data = '';

	/**
	 * Points the private folder at a temporary directory.
	 */
	public function private_dir(): string {
		return $this->data;
	}

	public function set_up(): void {
		parent::set_up();
		$this->data = sys_get_temp_dir() . '/ss-data-' . wp_generate_password( 6, false );
		add_filter( 'sentinel_shield_data_dir', array( $this, 'private_dir' ) );
		DataDir::recheck();
		global $wpdb;
		$c = Plugin::instance()->container();
		$wpdb->query( $wpdb->prepare( 'DELETE FROM %i', $c->get( BlockRepository::class )->table() ) );
		$wpdb->query( $wpdb->prepare( 'DELETE FROM %i', $c->get( EventRepository::class )->table() ) );
		$c->get( RuleCache::class )->flush();
		EarlyGate::delete_files();
	}

	public function tear_down(): void {
		if ( is_resource( $this->server ) ) {
			proc_terminate( $this->server );
			proc_close( $this->server );
		}
		if ( '' !== $this->docroot ) {
			array_map( 'unlink', (array) glob( $this->docroot . '/*' ) );
			@rmdir( $this->docroot ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		}
		EarlyGate::delete_files();
		EarlyGate::remove_loader();
		array_map( 'unlink', (array) glob( $this->data . '/*' ) );
		@rmdir( $this->data ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		remove_filter( 'sentinel_shield_data_dir', array( $this, 'private_dir' ) );
		delete_site_option( DataDir::OPTION );
		delete_site_option( Settings::OPTION );
		delete_site_option( CloudflareSync::TOKEN );
		delete_site_option( CloudflareSync::STATE );
		Plugin::instance()->container()->get( Settings::class )->refresh();
		parent::tear_down();
	}

	/**
	 * Saves settings (test mode off, trusted proxy on 127.0.0.1) and returns the gate.
	 *
	 * @param array<string, mixed> $extra More settings.
	 */
	private function gate( array $extra = array() ): EarlyGate {
		update_site_option(
			Settings::OPTION,
			array_replace_recursive(
				array(
					'general'  => array( 'test_mode' => false ),
					'proxy'    => array(
						'mode'          => 'custom',
						'header'        => 'X-Forwarded-For',
						'trusted_cidrs' => '127.0.0.1',
					),
					'firewall' => array( 'early_gate' => 'prepend' ),
				),
				$extra
			)
		);
		Plugin::instance()->container()->get( Settings::class )->refresh();
		return Plugin::instance()->container()->get( EarlyGate::class );
	}

	/**
	 * Starts PHP's server with the gate prepended, serving a stub page.
	 */
	private function start_server(): void {
		$this->docroot = sys_get_temp_dir() . '/ss-gate-' . wp_generate_password( 6, false );
		mkdir( $this->docroot );
		file_put_contents( $this->docroot . '/index.php', '<?php echo "REACHED:" . ( defined( "SENTINEL_SHIELD_EARLY_GATE" ) ? SENTINEL_SHIELD_EARLY_GATE : "none" );' );
		file_put_contents( $this->docroot . '/wp-cron.php', '<?php echo "CRON";' );
		for ( $attempt = 0; $attempt < 3; $attempt++ ) {
			// A port the system says is free right now.
			$probe = stream_socket_server( 'tcp://127.0.0.1:0' );
			$name  = (string) stream_socket_get_name( $probe, false );
			fclose( $probe );
			$this->port   = (int) substr( $name, strrpos( $name, ':' ) + 1 );
			$cmd          = array( PHP_BINARY, '-S', '127.0.0.1:' . $this->port, '-t', $this->docroot, '-d', 'auto_prepend_file=' . EarlyGate::gate_file() );
			$env          = array( 'SENTINEL_SHIELD_GATE_CONFIG' => EarlyGate::path() );
			$this->server = proc_open( $cmd, array( 1 => array( 'file', '/dev/null', 'w' ), 2 => array( 'file', '/dev/null', 'w' ) ), $pipes, null, $env );
			for ( $i = 0; $i < 50; $i++ ) {
				$sock = @fsockopen( '127.0.0.1', $this->port ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
				if ( $sock ) {
					fclose( $sock );
					return;
				}
				usleep( 100000 );
			}
			proc_terminate( $this->server );
			proc_close( $this->server );
		}
		$this->fail( 'PHP server did not start' );
	}

	/**
	 * Requests the stub site.
	 *
	 * @param string|null $ip   X-Forwarded-For value (null: none).
	 * @param string      $path Path and query.
	 * @return array{0:int, 1:string} Status and body.
	 */
	private function fetch( ?string $ip, string $path = '/' ): array {
		$headers = null === $ip ? '' : "X-Forwarded-For: $ip\r\n";
		$context = stream_context_create(
			array(
				'http' => array(
					'header'        => $headers,
					'ignore_errors' => true,
					'timeout'       => 5,
				),
			)
		);
		$body = (string) @file_get_contents( 'http://127.0.0.1:' . $this->port . $path, false, $context ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		preg_match( '/\s(\d{3})\s/', (string) ( $http_response_header[0] ?? '' ), $m );
		return array( (int) ( $m[1] ?? 0 ), $body );
	}

	public function test_snapshot_respects_test_mode_and_expiry(): void {
		$repo = Plugin::instance()->container()->get( BlockRepository::class );
		$repo->add( 'block', Cidr::parse( '203.0.113.0/24' ), 'manual', 'manual' );
		$repo->add( 'block', Cidr::parse( '198.51.100.5' ), 'lockout', 'lockout', time() + 600 );
		$repo->add( 'allow', Cidr::parse( '203.0.113.7' ), 'office', 'manual' );

		$data = $this->gate()->compile();
		$set  = IpRangeSet::from_strings( $data['blocked'] );
		$this->assertTrue( $set->contains( (string) inet_pton( '203.0.113.6' ) ) );
		$this->assertFalse( $set->contains( (string) inet_pton( '203.0.113.7' ) ), 'the allowlisted address is cut out of the exported policy' );
		$this->assertTrue( $set->contains( (string) inet_pton( '198.51.100.5' ) ) );
		$this->assertContains( '203.0.113.128/25', $data['blocked'] );
		$this->assertLessThanOrEqual( time() + 600, $data['snapshot']['valid_until'], 'expires with the lockout' );
		$this->assertTrue( $data['snapshot']['enabled'] );

		// Test mode for automatic rules only: lockouts are left out, manual rules stay.
		$data = $this->gate( array( 'general' => array( 'test_mode' => true, 'test_mode_scope' => 'automatic' ) ) )->compile();
		$this->assertFalse( IpRangeSet::from_strings( $data['blocked'] )->contains( (string) inet_pton( '198.51.100.5' ) ) );
		$this->assertTrue( IpRangeSet::from_strings( $data['blocked'] )->contains( (string) inet_pton( '203.0.113.1' ) ) );

		// Protection off, or the IP gate off: every layer gets an empty policy.
		$data = $this->gate( array( 'general' => array( 'enabled' => false ) ) )->compile();
		$this->assertFalse( $data['snapshot']['enabled'] );
		$this->assertSame( array(), $data['blocked'] );
		$data = $this->gate( array( 'modules' => array( 'ip_gate' => array( 'enabled' => false ) ) ) )->compile();
		$this->assertSame( array(), $data['blocked'] );
	}

	public function test_the_gate_blocks_before_anything_else_runs(): void {
		$c    = Plugin::instance()->container();
		$repo = $c->get( BlockRepository::class );
		$repo->add( 'block', Cidr::parse( '203.0.113.0/24' ), 'manual', 'manual' );
		$repo->add( 'allow', Cidr::parse( '203.0.113.7' ), 'office', 'manual' );
		$state = $this->gate()->rebuild();
		$this->assertSame( '', $state['error'] );
		$this->assertFileExists( EarlyGate::path() );
		$this->start_server();

		[ $code, $body ] = $this->fetch( '198.51.100.20' );
		$this->assertSame( array( 200, 'REACHED:prepend' ), array( $code, $body ), 'other visitors pass, and the gate ran' );

		[ $code, $body ] = $this->fetch( '203.0.113.50' );
		$this->assertSame( 403, $code );
		$this->assertStringContainsString( '203.0.113.50', $body );
		$this->assertStringContainsString( 'blocklist', $body );
		$this->assertStringNotContainsString( 'REACHED', $body );

		$this->assertSame( 200, $this->fetch( '203.0.113.7' )[0], 'allowlist wins' );
		$this->assertSame( 200, $this->fetch( '203.0.113.50', '/?sentinel_unlock=abc' )[0], 'unlock links reach WordPress' );
		$this->assertSame( 200, $this->fetch( '203.0.113.50', '/?sentinel_unlock_form=1' )[0] );
		$this->assertSame( 403, $this->fetch( '198.51.100.1, 203.0.113.50' )[0], 'the rightmost untrusted hop counts, not a spoofed left one' );
		$this->assertSame( 200, $this->fetch( '203.0.113.50, 198.51.100.1' )[0] );

		// Every block was noted for the event log.
		$this->assertGreaterThan( 0, $c->get( EarlyGate::class )->import_log() );
		$events = $c->get( EventRepository::class )->query( array() )[0];
		$this->assertSame( 'early_gate', $events[0]['module'] );

		// Emergency file: everything passes.
		touch( DataDir::path() . '/gate.disabled' );
		$this->assertSame( 200, $this->fetch( '203.0.113.50' )[0] );
		unlink( DataDir::path() . '/gate.disabled' );

		// A stale snapshot is not used.
		$json                = json_decode( (string) file_get_contents( EarlyGate::path() ), true );
		$json['valid_until'] = time() - 1;
		file_put_contents( EarlyGate::path(), wp_json_encode( $json ) );
		$this->assertSame( 200, $this->fetch( '203.0.113.50' )[0] );

		// Damaged: not used either.
		file_put_contents( EarlyGate::path(), '{broken' );
		$this->assertSame( 200, $this->fetch( '203.0.113.50' )[0] );
	}

	public function test_the_gate_blocks_blocklist_feed_ips(): void {
		global $wpdb;
		$feeds = Plugin::instance()->container()->get( \SentinelShield\Repository\FeedRepository::class );
		$wpdb->query( $wpdb->prepare( 'DELETE FROM %i', $feeds->table() ) );
		foreach ( array( '192.0.2.0/24', '2001:db8:dead::/48' ) as $range ) {
			$c = Cidr::parse( $range );
			$wpdb->query( $wpdb->prepare( 'INSERT INTO %i (feed, ip_version, ip_start, ip_end, prefix) VALUES (%s, %d, UNHEX(%s), UNHEX(%s), %d)', $feeds->table(), 'spamhaus_drop', $c->version, bin2hex( $c->start ), bin2hex( $c->end ), $c->prefix ) );
		}
		Plugin::instance()->container()->get( RuleCache::class )->flush_feeds();
		$state = $this->gate( array( 'feeds' => array( 'lists' => array( 'spamhaus_drop' => true ) ) ) )->rebuild();
		$this->assertTrue( $state['feeds'] );
		$this->start_server();
		[ $code, $body ] = $this->fetch( '192.0.2.77' );
		$this->assertSame( 403, $code );
		$this->assertStringContainsString( 'public blocklist', $body );
		$this->assertSame( 403, $this->fetch( '2001:db8:dead::1' )[0] );
		$this->assertSame( 200, $this->fetch( '192.0.3.1' )[0] );
		$this->assertSame( 200, $this->fetch( '2001:db8:beef::1' )[0] );
	}

	public function test_proxy_fallback_requests_are_left_to_wordpress(): void {
		$repo = Plugin::instance()->container()->get( BlockRepository::class );
		$repo->add( 'allow', Cidr::parse( '127.0.0.1' ), 'proxy', 'manual' );
		$repo->add( 'block', Cidr::parse( '127.0.0.0/8' ), 'test', 'manual' );
		$this->gate()->rebuild();
		$this->start_server();
		// The exported policy never blocks allowlisted or server addresses, so the early
		// gate leaves this case to WordPress (which ignores the allowlist for it).
		$this->assertSame( 200, $this->fetch( null )[0], 'the early gate never blocks more than WordPress' );
		$this->assertSame( 'CRON', $this->fetch( null, '/wp-cron.php' )[1], 'cron from this server always passes' );
	}

	public function test_loader_server_files_and_the_malware_scan(): void {
		$gate = $this->gate( array( 'firewall' => array( 'early_gate' => 'mu_plugin', 'server_files' => true ) ) );
		Plugin::instance()->container()->get( BlockRepository::class )->add( 'block', Cidr::parse( '203.0.113.0/24' ), 'manual', 'manual' );
		$this->assertSame( '', $gate->sync_loader() );
		$this->assertTrue( EarlyGate::is_own_loader( EarlyGate::loader_path() ) );
		$gate->rebuild();
		$dir = DataDir::path();
		$this->assertStringContainsString( 'deny 203.0.113.0/24;', (string) file_get_contents( $dir . '/nginx-deny.conf' ) );
		$this->assertStringContainsString( 'Require not ip 203.0.113.0/24', (string) file_get_contents( $dir . '/apache-deny.conf' ) );

		// The scan does not flag our own loader, but does flag a changed one.
		$c       = Plugin::instance()->container();
		$scanner = $c->get( IntegrityScanner::class );
		$mine    = array_filter( $scanner->run( true )['findings'], static fn( array $f ): bool => str_contains( (string) $f['title'], EarlyGate::LOADER ) );
		$this->assertSame( array(), $mine );
		file_put_contents( EarlyGate::loader_path(), "\n// changed", FILE_APPEND );
		$mine = array_filter( $scanner->run( true )['findings'], static fn( array $f ): bool => str_contains( (string) $f['title'], EarlyGate::LOADER ) );
		$this->assertNotEmpty( $mine );

		// Switching off removes our loader, even a tampered one, but never someone else's file.
		$gate = $this->gate( array( 'firewall' => array( 'early_gate' => 'off' ) ) );
		$gate->sync_loader();
		$this->assertFileDoesNotExist( EarlyGate::loader_path() );
		file_put_contents( EarlyGate::loader_path(), "<?php\n// Someone else's must-use plugin with the same name.\n" );
		$gate->sync_loader();
		$this->assertFileExists( EarlyGate::loader_path() );
		unlink( EarlyGate::loader_path() );
	}

	public function test_scan_trusts_its_own_gate_only_while_it_matches_the_release(): void {
		$this->assertTrue( EarlyGate::is_own_gate( EarlyGate::gate_file() ) );
		$this->assertFalse( EarlyGate::is_own_gate( __FILE__ ) );
		$list = dirname( SENTINEL_SHIELD_FILE ) . '/checksums.sha256';
		$this->assertFileDoesNotExist( $list, 'development copy has no checksum list' );
		$this->assertTrue( IntegrityScanner::own_file_intact( EarlyGate::gate_file() ), 'no list: trusted' );
		try {
			file_put_contents( $list, hash_file( 'sha256', EarlyGate::gate_file() ) . "  early-gate.php\n" );
			$this->assertTrue( IntegrityScanner::own_file_intact( EarlyGate::gate_file() ) );
			file_put_contents( $list, str_repeat( '0', 64 ) . "  early-gate.php\n" );
			$this->assertFalse( IntegrityScanner::own_file_intact( EarlyGate::gate_file() ), 'changed gate: reported' );
		} finally {
			unlink( $list );
		}
	}

	public function test_exports_match_what_wordpress_blocks(): void {
		$repo = Plugin::instance()->container()->get( BlockRepository::class );
		$repo->add( 'block', Cidr::parse( '203.0.113.0/24' ), 'manual', 'manual' );
		$repo->add( 'allow', Cidr::parse( '203.0.113.7' ), 'admin', 'admin_auto' );
		$repo->add( 'block', Cidr::parse( '2001:db8::/48' ), 'manual', 'manual' );
		$repo->add( 'allow', Cidr::parse( '2001:db8::10/124' ), 'office', 'manual' );
		$repo->add( 'block', Cidr::parse( '127.0.0.0/8' ), 'oops', 'manual' );
		$gate = $this->gate( array( 'firewall' => array( 'server_files' => true ) ) );
		$gate->rebuild();
		$nginx = (string) file_get_contents( DataDir::path() . '/nginx-deny.conf' );
		$denied = IpRangeSet::from_strings( array_map( static fn( string $l ): string => substr( $l, 5, -1 ), array_values( array_filter( explode( "\n", $nginx ), static fn( string $l ): bool => str_starts_with( $l, 'deny ' ) ) ) ) );
		$wp     = Plugin::instance()->container()->get( \SentinelShield\Firewall\Gate::class );
		Plugin::instance()->container()->get( RuleCache::class )->flush();
		foreach ( array( '203.0.113.6', '203.0.113.7', '203.0.113.8', '2001:db8::f', '2001:db8::10', '2001:db8::1f', '2001:db8::20', '127.0.0.1' ) as $ip ) {
			$this->assertSame( $wp->evaluate( $ip, '/', false, true )->is_block() && ! str_starts_with( $ip, '127.' ), $denied->contains( (string) inet_pton( $ip ) ), "nginx and WordPress agree on $ip" );
		}
		$this->assertStringNotContainsString( '127.0.0', $nginx, 'this server is never blocked at the server' );
		$apache = (string) file_get_contents( DataDir::path() . '/apache-deny.conf' );
		$this->assertStringNotContainsString( 'Require not ip 203.0.113.0/24', $apache );
		$this->assertStringContainsString( "Require not ip 203.0.113.6\n", $apache );
		$this->assertStringNotContainsString( 'Require not ip 203.0.113.7', $apache );
	}

	public function test_nothing_sensitive_is_written_to_an_unconfirmed_folder(): void {
		Plugin::instance()->container()->get( BlockRepository::class )->add( 'block', Cidr::parse( '203.0.113.0/24' ), 'manual', 'manual' );
		$public = ABSPATH . 'ss-public-' . wp_generate_password( 6, false );
		$filter = static fn(): string => $public;
		add_filter( 'sentinel_shield_data_dir', $filter, 20 );
		$_SERVER['DOCUMENT_ROOT'] = ABSPATH;
		// The web server serves the probe file: the folder is public.
		$serve = static function ( $pre, array $args, string $url ) use ( $public ) {
			$file = $public . '/' . basename( (string) wp_parse_url( $url, PHP_URL_PATH ) );
			return is_file( $file ) ? array( 'response' => array( 'code' => 200 ), 'body' => (string) file_get_contents( $file ) ) : array( 'response' => array( 'code' => 404 ), 'body' => '' );
		};
		$offline = static fn() => new \WP_Error( 'http_request_failed', 'unreachable' );
		try {
			add_filter( 'pre_http_request', $serve, 10, 3 );
			$this->assertFalse( DataDir::recheck(), 'downloadable over HTTP' );
			remove_filter( 'pre_http_request', $serve, 10 );
			$state = $this->gate( array( 'firewall' => array( 'server_files' => true ) ) )->rebuild();
			$this->assertStringContainsString( 'downloaded over the web', $state['error'] );
			$this->assertFileDoesNotExist( $public . '/gate.json' );
			$this->assertFileDoesNotExist( $public . '/nginx-deny.conf' );

			add_filter( 'pre_http_request', $offline );
			$this->assertNull( DataDir::recheck(), 'the site cannot reach itself: not confirmed' );
			remove_filter( 'pre_http_request', $offline );
			$state = $this->gate( array( 'firewall' => array( 'server_files' => true ) ) )->rebuild();
			$this->assertStringContainsString( 'Could not confirm', $state['error'] );
			$this->assertFileDoesNotExist( $public . '/gate.json' );
		} finally {
			remove_filter( 'pre_http_request', $serve, 10 );
			remove_filter( 'pre_http_request', $offline );
			unset( $_SERVER['DOCUMENT_ROOT'] );
			remove_filter( 'sentinel_shield_data_dir', $filter, 20 );
			@rmdir( $public ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			DataDir::recheck();
		}
	}

	public function test_deactivation_stops_every_layer(): void {
		Plugin::instance()->container()->get( BlockRepository::class )->add( 'block', Cidr::parse( '203.0.113.0/24' ), 'manual', 'manual' );
		$gate = $this->gate( array( 'firewall' => array( 'early_gate' => 'mu_plugin', 'server_files' => true ) ) );
		$gate->sync_loader();
		$gate->rebuild();
		$this->assertFileExists( EarlyGate::path() );
		EarlyGate::deactivate();
		$this->assertFileDoesNotExist( EarlyGate::path(), 'a prepend line left behind finds no snapshot and lets everything through' );
		$this->assertFileDoesNotExist( EarlyGate::loader_path() );
		$this->assertStringNotContainsString( 'deny ', (string) file_get_contents( DataDir::path() . '/nginx-deny.conf' ), 'emptied, not deleted' );
	}

	/**
	 * Fake Cloudflare API: records calls; answers PUT with an operation ID and
	 * the bulk operation status with $this->cf_status.
	 *
	 * @var list<array{0:string, 1:array<string, mixed>}>
	 */
	private array $cf_calls = array();

	private string $cf_status = 'completed';

	private bool $cf_fail = false;

	public function fake_cloudflare( $pre, array $args, string $url ) {
		$this->cf_calls[] = array( $url, $args );
		if ( $this->cf_fail ) {
			return array(
				'response' => array( 'code' => 400 ),
				'body'     => (string) wp_json_encode( array( 'success' => false, 'errors' => array( array( 'message' => 'bad item' ) ) ) ),
			);
		}
		$result = str_contains( $url, '/bulk_operations/' ) ? array( 'status' => $this->cf_status ) : ( 'PUT' === $args['method'] ? array( 'operation_id' => 'op123' ) : array( 'kind' => 'ip', 'name' => 'blocked', 'num_items' => 2 ) );
		return array(
			'response' => array( 'code' => 200 ),
			'body'     => (string) wp_json_encode( array( 'success' => true, 'result' => $result ) ),
		);
	}

	public function test_cloudflare_sync_follows_the_policy_and_its_completion(): void {
		$items = CloudflareSync::items( array( '203.0.113.5', '10.0.0.0/8', '1.0.0.0/7', '2001:db8::1', '2001:db8:1::/48', 'junk' ) );
		$this->assertSame( array( '203.0.113.5', '10.0.0.0/8', '2001:db8:1::/48' ), $items['items'] );
		$this->assertSame( 2, $items['skipped'], 'a /7 and a single IPv6 address are left out by default' );
		$wide = CloudflareSync::items( array( '2001:db8::1', '2001:db8:5::1' ), 'expand', IpRangeSet::from_strings( array( '2001:db8:5::99' ) ) );
		$this->assertSame( array( '2001:db8::/64' ), $wide['items'] );
		$this->assertSame( array( 1, 1 ), array( $wide['expanded'], $wide['skipped'] ), 'never widened over an allowlisted address' );

		$repo = Plugin::instance()->container()->get( BlockRepository::class );
		$repo->add( 'block', Cidr::parse( '203.0.113.0/30' ), 'manual', 'manual' );
		$repo->add( 'allow', Cidr::parse( '203.0.113.2' ), 'office', 'manual' );
		$this->gate(
			array(
				'cloudflare' => array(
					'sync'       => true,
					'account_id' => str_repeat( 'a', 32 ),
					'list_id'    => str_repeat( 'b', 32 ),
				),
			)
		);
		$sync = Plugin::instance()->container()->get( CloudflareSync::class );
		$this->assertFalse( $sync->enabled(), 'no token yet' );
		$sync->set_token( 'secret-token' );
		$this->assertStringNotContainsString( 'secret-token', (string) get_site_option( CloudflareSync::TOKEN ), 'stored encrypted' );
		add_filter( 'pre_http_request', array( $this, 'fake_cloudflare' ), 10, 3 );
		try {
			$state = $sync->sync();
			$this->assertSame( 'applying', $state['status'], 'accepted is not yet applied' );
			$this->assertSame( 'https://api.cloudflare.com/client/v4/accounts/' . str_repeat( 'a', 32 ) . '/rules/lists/' . str_repeat( 'b', 32 ) . '/items', $this->cf_calls[0][0] );
			$this->assertSame( 'Bearer secret-token', $this->cf_calls[0][1]['headers']['Authorization'] );
			$this->assertSame( array( '203.0.113.0/31', '203.0.113.3' ), array_column( json_decode( $this->cf_calls[0][1]['body'], true ), 'ip' ), 'the allowlisted address is not sent' );

			$this->cf_status = 'running';
			$this->assertSame( 'applying', $sync->check_operation()['status'] );
			$this->assertStringContainsString( '/bulk_operations/op123', end( $this->cf_calls )[0] );
			$this->cf_status = 'completed';
			$this->assertSame( 'active', $sync->check_operation()['status'] );

			// Scheduled syncs: an unchanged list is not uploaded again, and a
			// changed one waits for the minimum interval; Sync now always uploads.
			$calls = count( $this->cf_calls );
			$sync->sync();
			$this->assertCount( $calls, $this->cf_calls, 'unchanged list not re-uploaded' );
			$repo->add( 'block', Cidr::parse( '198.51.100.7' ), 'manual', 'manual' );
			wp_clear_scheduled_hook( CloudflareSync::CRON );
			$sync->sync();
			$this->assertCount( $calls, $this->cf_calls, 'changed, but uploaded less than five minutes ago' );
			$this->assertGreaterThan( time() + 200, (int) wp_next_scheduled( CloudflareSync::CRON ), 'retried after the interval' );
			$this->assertSame( 'applying', $sync->sync( true )['status'] );
			$this->assertCount( $calls + 1, $this->cf_calls );
			$this->assertContains( '198.51.100.7', array_column( json_decode( end( $this->cf_calls )[1]['body'], true ), 'ip' ) );
			$this->cf_status = 'completed';
			$sync->check_operation();
			wp_clear_scheduled_hook( CloudflareSync::CRON );

			// Protection switched off: the list is emptied at once, interval or not.
			$this->gate( array( 'general' => array( 'enabled' => false ), 'cloudflare' => array( 'sync' => true, 'account_id' => str_repeat( 'a', 32 ), 'list_id' => str_repeat( 'b', 32 ) ) ) );
			$sync->sync();
			$this->assertSame( array(), json_decode( end( $this->cf_calls )[1]['body'], true ) );

			// Sync switched off: emptied too; and a failure says the rules are still active.
			$this->gate( array( 'cloudflare' => array( 'sync' => true, 'account_id' => str_repeat( 'a', 32 ), 'list_id' => str_repeat( 'b', 32 ) ) ) );
			$sync->sync( true );
			$this->cf_fail = true;
			$this->assertFalse( $sync->clear_remote( 'test' ) );
			$this->assertStringContainsString( 'still active at Cloudflare', CloudflareSync::state()['error'] );
			$this->cf_fail = false;
			$this->assertTrue( $sync->clear_remote( 'test' ) );
			$this->assertSame( 'cleared', CloudflareSync::state()['status'] );

			$test = $sync->test();
			$this->assertTrue( $test['ok'] );
		} finally {
			remove_filter( 'pre_http_request', array( $this, 'fake_cloudflare' ), 10 );
		}
	}
}
