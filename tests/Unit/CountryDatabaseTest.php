<?php
/**
 * Country database: building from CSV and lookups.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SentinelShield\Geo\CountryDatabase;
use SentinelShield\Geo\CountryList;

final class CountryDatabaseTest extends TestCase {

	private string $dir;

	protected function setUp(): void {
		$this->dir = sys_get_temp_dir() . '/ss-geo-' . bin2hex( random_bytes( 4 ) );
		mkdir( $this->dir );
	}

	protected function tearDown(): void {
		foreach ( (array) glob( $this->dir . '/*' ) as $file ) {
			CountryDatabase::close( (string) $file );
			unlink( (string) $file );
		}
		rmdir( $this->dir );
	}

	private function build( string $csv ): CountryDatabase {
		$src = $this->dir . '/in.csv';
		file_put_contents( $src, $csv );
		CountryDatabase::build( $src, $this->dir . '/db.bin' );
		return new CountryDatabase( $this->dir . '/db.bin' );
	}

	private function fixture_db(): CountryDatabase {
		return $this->build( (string) file_get_contents( dirname( __DIR__ ) . '/fixtures/geo/country.csv' ) );
	}

	public function test_lookups_boundaries_and_gaps(): void {
		$db    = $this->fixture_db();
		$cases = array(
			'1.0.0.0'                 => 'AU',
			'1.0.0.255'               => 'AU',
			'1.0.1.0'                 => 'CN',
			'1.0.4.255'               => 'CN',
			'1.0.5.0'                 => '',
			'8.8.8.8'                 => 'US',
			'0.0.0.1'                 => '',
			'10.1.2.3'                => '',
			'81.2.69.142'             => 'GB',
			'203.0.113.255'           => 'FR',
			'203.0.114.0'             => '',
			'255.255.255.255'         => '',
			'2001:4860:4860::8888'    => 'US',
			'2a00:1450:4001:80b::200e' => 'DE',
			'2a00:1451::'             => '',
			'::1'                     => '',
		);
		foreach ( $cases as $ip => $expected ) {
			$this->assertSame( $expected, $db->lookup( (string) inet_pton( $ip ) ), $ip );
		}
		$this->assertSame( '', $db->lookup( 'bad' ) );
	}

	public function test_merges_adjacent_ranges_and_skips_unknown(): void {
		$info = $this->fixture_db()->info();
		$this->assertNotNull( $info );
		// AU, CN (three rows merged), US, GB, US, FR.
		$this->assertSame( 6, $info['v4'] );
		$this->assertSame( 2, $info['v6'] );
	}

	public function test_reads_gzip(): void {
		$src = $this->dir . '/in.csv.gz';
		file_put_contents( $src, gzencode( "8.8.8.0,8.8.8.255,US\n9.9.9.0,9.9.9.255,CH\n" ) );
		CountryDatabase::build( $src, $this->dir . '/db.bin' );
		$db = new CountryDatabase( $this->dir . '/db.bin' );
		$this->assertSame( 'CH', $db->lookup( (string) inet_pton( '9.9.9.9' ) ) );
	}

	public function test_rejects_unsorted_or_overlapping_input(): void {
		foreach ( array( "8.8.8.0,8.8.8.255,US\n1.0.0.0,1.0.0.255,AU\n", "1.0.0.0,1.0.1.255,AU\n1.0.1.0,1.0.2.255,CN\n", "1.0.0.9,1.0.0.1,AU\n" ) as $csv ) {
			try {
				$this->build( $csv );
				$this->fail( 'Accepted: ' . $csv );
			} catch ( \RuntimeException $e ) {
				$this->assertNotSame( '', $e->getMessage() );
			}
		}
	}

	public function test_missing_or_damaged_file_is_unknown(): void {
		$db = new CountryDatabase( $this->dir . '/none.bin' );
		$this->assertNull( $db->info() );
		$this->assertSame( '', $db->lookup( (string) inet_pton( '8.8.8.8' ) ) );

		$this->fixture_db();
		$path = $this->dir . '/db.bin';
		CountryDatabase::close( $path );
		file_put_contents( $path, substr( (string) file_get_contents( $path ), 0, -5 ) );
		$this->assertNull( ( new CountryDatabase( $path ) )->info(), 'truncated file is rejected' );
	}

	public function test_country_list_parse(): void {
		$this->assertSame( array( array( 'US', 'GB', 'T1' ), array( 'XX', 'USA' ) ), CountryList::parse( "us, xx; GB gb\nT1 USA" ) );
		$this->assertSame( 'DE (Germany)', CountryList::label( 'DE' ) );
	}
}
