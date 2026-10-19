<?php
/**
 * Filesystem failures: permissions, symlinks, missing and replaced files.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Tests\Integration;

use SentinelShield\Firewall\EarlyGate;
use SentinelShield\Firewall\RuleCache;
use SentinelShield\Net\Cidr;
use SentinelShield\Plugin;
use SentinelShield\Repository\BlockRepository;
use SentinelShield\Safety\Health;
use SentinelShield\Settings;
use SentinelShield\Support\DataDir;

/**
 * Review 5 (P1): each failure produces an accurate health report, nothing
 * sensitive is written where it should not be, and the previous working
 * policy stays in place. (Disk-full and short writes: EarlyGateTest and
 * bin/fault-test.sh.)
 */
final class FilesystemFailureTest extends \WP_UnitTestCase {

	private string $tmp = '';

	private string $data = '';

	public function private_dir(): string {
		return $this->data;
	}

	public function set_up(): void {
		parent::set_up();
		if ( function_exists( 'posix_geteuid' ) && 0 === posix_geteuid() ) {
			$this->markTestSkipped( 'File permissions do not apply to root.' );
		}
		$this->tmp  = get_temp_dir() . 'ss-fs-' . wp_generate_password( 6, false );
		$this->data = $this->tmp . '/data';
		wp_mkdir_p( $this->tmp );
		add_filter( 'sentinel_shield_data_dir', array( $this, 'private_dir' ) );
		$_SERVER['DOCUMENT_ROOT'] = ABSPATH;
		update_site_option(
			Settings::OPTION,
			array(
				'general'  => array( 'test_mode' => false ),
				'firewall' => array( 'early_gate' => 'mu_plugin' ),
			)
		);
		$c = Plugin::instance()->container();
		$c->get( Settings::class )->refresh();
		global $wpdb;
		$wpdb->query( $wpdb->prepare( 'DELETE FROM %i', $c->get( BlockRepository::class )->table() ) );
		$c->get( BlockRepository::class )->add( 'block', Cidr::parse( '203.0.113.0/24' ), 'fs', 'manual' );
		$c->get( RuleCache::class )->flush();
		add_filter( 'pre_http_request', array( self::class, 'offline' ) );
	}

	public function tear_down(): void {
		remove_filter( 'pre_http_request', array( self::class, 'offline' ) );
		remove_filter( 'sentinel_shield_data_dir', array( $this, 'private_dir' ) );
		if ( '' !== $this->tmp ) {
			exec( 'chmod -R u+rwx ' . escapeshellarg( $this->tmp ) . ' && rm -rf ' . escapeshellarg( $this->tmp ) );
		}
		foreach ( array( Settings::OPTION, DataDir::OPTION, DataDir::ROOT, EarlyGate::STATE, EarlyGate::DIRTY ) as $option ) {
			delete_site_option( $option );
		}
		unset( $_SERVER['DOCUMENT_ROOT'] );
		Plugin::instance()->container()->get( Settings::class )->refresh();
		parent::tear_down();
	}

	/**
	 * The web server cannot be asked anything (HTTP probes fail).
	 */
	public static function offline(): \WP_Error {
		return new \WP_Error( 'http_request_failed', 'offline' );
	}

	private static function gate(): EarlyGate {
		return Plugin::instance()->container()->get( EarlyGate::class );
	}

	/**
	 * Health rows by id.
	 *
	 * @return array<string, array{state:string, detail:string}>
	 */
	private static function health(): array {
		$rows = array();
		foreach ( ( new Health( Plugin::instance()->container() ) )->checks() as $row ) {
			$rows[ $row['id'] ] = $row;
		}
		return $rows;
	}

	public function test_a_folder_swapped_for_a_symlink_into_the_web_root_is_checked_again(): void {
		$this->assertTrue( DataDir::is_private() );
		$this->assertSame( '', self::gate()->rebuild()['error'] );
		$this->assertFileExists( EarlyGate::path() );

		// Someone replaces the approved folder with a link into the web root.
		$public = ABSPATH . 'ss-public-' . wp_generate_password( 6, false );
		mkdir( $public );
		try {
			exec( 'rm -rf ' . escapeshellarg( $this->data ) );
			symlink( $public, $this->data );
			$this->assertNull( DataDir::is_private(), 'checked again: inside the web root and unconfirmed' );
			$state = self::gate()->rebuild();
			$this->assertNotSame( '', $state['error'] );
			$this->assertSame( array(), glob( $public . '/gate*' ), 'nothing written into the web root' );
			$this->assertSame( 'bad', self::health()['private']['state'] );
		} finally {
			@unlink( $this->data ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			exec( 'rm -rf ' . escapeshellarg( $public ) );
		}
	}

	public function test_a_folder_that_cannot_be_created_is_reported(): void {
		chmod( $this->tmp, 0555 );
		$this->assertNull( DataDir::recheck() );
		$this->assertStringContainsString( 'could not be created', DataDir::problem() );
		$this->assertNotSame( '', self::gate()->rebuild()['error'] );
		$this->assertSame( 'bad', self::health()['private']['state'] );
	}

	public function test_a_folder_that_became_read_only_keeps_the_previous_policy_and_says_so(): void {
		$first = self::gate()->rebuild();
		$this->assertSame( $first['generation'], $first['published'] );
		$json = (string) file_get_contents( EarlyGate::path() );
		Plugin::instance()->container()->get( BlockRepository::class )->add( 'block', Cidr::parse( '198.51.100.9' ), 'fs', 'manual' );
		chmod( $this->data, 0555 );
		$state = self::gate()->rebuild();
		$this->assertSame( $first['published'], $state['published'] );
		$this->assertSame( $json, (string) file_get_contents( EarlyGate::path() ), 'the previous policy is still in place' );
		$health = self::health();
		$this->assertSame( 'bad', $health['private']['state'] );
		$this->assertStringContainsString( 'not writable', $health['private']['detail'] );
		$this->assertTrue( self::gate()->publication()['pending'], 'the change waits for publication' );
		chmod( $this->data, 0755 );
		$state = self::gate()->rebuild();
		$this->assertSame( $state['generation'], $state['published'] );
	}

	public function test_missing_range_files_are_reported_and_rebuilt(): void {
		$state = self::gate()->rebuild();
		$this->assertTrue( Health::snapshot_complete() );
		wp_delete_file( $state['files']['block'] );
		$this->assertFalse( Health::snapshot_complete() );
		$early = self::health()['early'];
		$this->assertSame( 'warn', $early['state'] );
		$this->assertStringContainsString( 'missing or damaged', $early['detail'] );
		self::gate()->rebuild();
		$this->assertTrue( Health::snapshot_complete() );
		// A truncated file counts as damaged too.
		$json = json_decode( (string) file_get_contents( EarlyGate::path() ), true );
		file_put_contents( $json['allow_file'], 'SSFEED1' );
		$this->assertFalse( Health::snapshot_complete() );
	}

	public function test_a_symlinked_snapshot_is_replaced_not_written_through(): void {
		self::gate()->rebuild();
		$elsewhere = $this->tmp . '/precious.txt';
		file_put_contents( $elsewhere, 'do not overwrite' );
		unlink( EarlyGate::path() );
		symlink( $elsewhere, EarlyGate::path() );
		Plugin::instance()->container()->get( BlockRepository::class )->add( 'block', Cidr::parse( '198.51.100.10' ), 'fs', 'manual' );
		self::gate()->rebuild();
		$this->assertSame( 'do not overwrite', (string) file_get_contents( $elsewhere ), 'the link target is untouched' );
		$this->assertFalse( is_link( EarlyGate::path() ), 'the link was replaced by the real snapshot' );
		$this->assertTrue( Health::snapshot_complete() );
	}
}
