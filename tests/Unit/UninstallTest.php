<?php
/**
 * uninstall.php keeps up with the schema.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Tests\Unit;

use PHPUnit\Framework\TestCase;

final class UninstallTest extends TestCase {

	/**
	 * Every table the schema creates is dropped on uninstall (0.8.2 missed one).
	 */
	public function test_uninstall_drops_every_table_the_schema_creates(): void {
		$root = dirname( __DIR__, 2 );
		preg_match_all( '/CREATE TABLE \{\$p\}(\w+)/', (string) file_get_contents( $root . '/src/Install/Schema.php' ), $created );
		$uninstall = (string) file_get_contents( $root . '/uninstall.php' );
		$this->assertNotEmpty( $created[1] );
		foreach ( $created[1] as $table ) {
			$this->assertStringContainsString( "'$table'", $uninstall, "uninstall.php does not drop $table" );
		}
	}
}
