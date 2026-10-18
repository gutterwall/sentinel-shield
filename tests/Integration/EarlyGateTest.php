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
use SentinelShield\Geo\GeoUpdater;
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

	public function set_up(): void {
		parent::set_up();
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
		foreach ( array( 'gate.disabled', 'early-blocks.log' ) as $file ) {
			if ( is_file( GeoUpdater::dir() . '/' . $file ) ) {
				unlink( GeoUpdater::dir() . '/' . $file );
			}
		}
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
		$this->assertEqualsCanonicalizing( array( '203.0.113.0/24', '198.51.100.5' ), $data['blocked'] );
		$this->assertLessThanOrEqual( time() + 600, $data['snapshot']['valid_until'], 'expires with the lockout' );
		$this->assertTrue( $data['snapshot']['enabled'] );

		// Test mode for automatic rules only: lockouts are left out, manual rules stay.
		$data = $this->gate( array( 'general' => array( 'test_mode' => true, 'test_mode_scope' => 'automatic' ) ) )->compile();
		$this->assertSame( array( '203.0.113.0/24' ), $data['blocked'] );

		$data = $this->gate( array( 'general' => array( 'enabled' => false ) ) )->compile();
		$this->assertFalse( $data['snapshot']['enabled'] );
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
		touch( GeoUpdater::dir() . '/gate.disabled' );
		$this->assertSame( 200, $this->fetch( '203.0.113.50' )[0] );
		unlink( GeoUpdater::dir() . '/gate.disabled' );

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

	public function test_requests_without_a_visitor_address_get_no_allowlist_privilege(): void {
		$repo = Plugin::instance()->container()->get( BlockRepository::class );
		$repo->add( 'allow', Cidr::parse( '127.0.0.1' ), 'proxy', 'manual' );
		$repo->add( 'block', Cidr::parse( '127.0.0.0/8' ), 'test', 'manual' );
		$this->gate()->rebuild();
		$this->start_server();
		$this->assertSame( 403, $this->fetch( null )[0], 'the proxy did not name a visitor: its allowlist entry does not apply' );
		$this->assertSame( 'CRON', $this->fetch( null, '/wp-cron.php' )[1], 'cron from this server always passes' );
	}

	public function test_loader_server_files_and_the_malware_scan(): void {
		$gate = $this->gate( array( 'firewall' => array( 'early_gate' => 'mu_plugin', 'server_files' => true ) ) );
		Plugin::instance()->container()->get( BlockRepository::class )->add( 'block', Cidr::parse( '203.0.113.0/24' ), 'manual', 'manual' );
		$this->assertSame( '', $gate->sync_loader() );
		$this->assertTrue( EarlyGate::is_own_loader( EarlyGate::loader_path() ) );
		$gate->rebuild();
		$dir = GeoUpdater::dir();
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

	public function test_cloudflare_items_and_sync(): void {
		$this->assertSame(
			array( '203.0.113.5', '10.0.0.0/8', '2001:db8::/64', '2001:db8:1::/48' ),
			CloudflareSync::items( array( '203.0.113.5/32', '10.0.0.0/8', '1.0.0.0/7', '2001:db8::1/128', '2001:db8::/112', '2001:db8:1::/48', 'junk' ) )
		);

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
		$this->assertTrue( $sync->enabled() );
		$this->assertStringNotContainsString( 'secret-token', (string) get_site_option( CloudflareSync::TOKEN ), 'stored encrypted' );

		$calls = array();
		$fake  = static function ( $pre, array $args, string $url ) use ( &$calls ) {
			$calls[] = array( $url, $args );
			$ok      = ! str_contains( (string) ( $args['body'] ?? '' ), '198.51.100.99' );
			return array(
				'response' => array( 'code' => $ok ? 200 : 400 ),
				'body'     => (string) wp_json_encode( $ok ? array( 'success' => true, 'result' => array( 'kind' => 'ip', 'name' => 'blocked', 'num_items' => 2 ) ) : array( 'success' => false, 'errors' => array( array( 'message' => 'bad item' ) ) ) ),
			);
		};
		add_filter( 'pre_http_request', $fake, 10, 3 );
		try {
			$state = $sync->sync( array( '203.0.113.5/32', '10.0.0.0/8' ) );
			$this->assertTrue( $state['ok'] );
			$this->assertSame( 2, $state['count'] );
			$this->assertSame( 'https://api.cloudflare.com/client/v4/accounts/' . str_repeat( 'a', 32 ) . '/rules/lists/' . str_repeat( 'b', 32 ) . '/items', $calls[0][0] );
			$this->assertSame( 'PUT', $calls[0][1]['method'] );
			$this->assertSame( 'Bearer secret-token', $calls[0][1]['headers']['Authorization'] );
			$this->assertSame( array( '203.0.113.5', '10.0.0.0/8' ), array_column( json_decode( $calls[0][1]['body'], true ), 'ip' ) );

			$state = $sync->sync( array( '198.51.100.99/32' ) );
			$this->assertFalse( $state['ok'] );
			$this->assertStringContainsString( 'bad item', $state['error'] );

			$test = $sync->test();
			$this->assertTrue( $test['ok'] );
			$this->assertStringContainsString( 'blocked', $test['message'] );
		} finally {
			remove_filter( 'pre_http_request', $fake, 10 );
		}
	}
}
