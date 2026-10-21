<?php
/**
 * bin/coverage-check.php: floors, and required measurements.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Tests\Unit;

use PHPUnit\Framework\TestCase;

/**
 * Review 6 (mandatory coverage evidence): a job that advertises a
 * measurement fails when the report is missing or empty, or does not cover a
 * source file of a group, instead of skipping the floor.
 */
final class CoverageCheckTest extends TestCase {

	private string $dir = '';

	private string $root = '';

	protected function setUp(): void {
		$this->root = dirname( __DIR__, 2 ) . '/';
		$this->dir  = sys_get_temp_dir() . '/ss-covcheck-' . bin2hex( random_bytes( 4 ) );
		mkdir( $this->dir );
		file_put_contents(
			$this->dir . '/baseline.json',
			json_encode(
				array(
					'goals'  => array(
						'overall_lines'     => 90,
						'security_branches' => 95,
					),
					'groups' => array(
						'recovery' => array(
							'paths'    => array( 'src/Unlock/' ),
							'lines'    => 80,
							'branches' => 50,
						),
					),
				)
			)
		);
		$this->clover( array( 'src/Unlock/UnlockForm.php' => array( 9, 10 ), 'src/Unlock/UnlockService.php' => array( 90, 100 ) ) );
	}

	protected function tearDown(): void {
		exec( 'rm -rf ' . escapeshellarg( $this->dir ) );
	}

	/**
	 * Writes a Clover report: file => [covered, statements].
	 *
	 * @param array<string, array{0:int, 1:int}> $files Files.
	 */
	private function clover( array $files ): void {
		$xml = '<?xml version="1.0"?><coverage><project>';
		foreach ( $files as $file => [ $covered, $total ] ) {
			$xml .= sprintf( '<file name="%s"><metrics statements="%d" coveredstatements="%d"/></file>', htmlspecialchars( $this->root . $file ), $total, $covered );
		}
		file_put_contents( $this->dir . '/clover.xml', $xml . '</project></coverage>' );
	}

	/**
	 * Writes a branch report: file => [hit, branches].
	 *
	 * @param array<string, array{0:int, 1:int}> $files Files.
	 */
	private function branches( array $files ): string {
		$out = array();
		foreach ( $files as $file => [ $hit, $total ] ) {
			$out[ $file ] = array(
				'branches' => $total,
				'hit'      => $hit,
			);
		}
		file_put_contents( $this->dir . '/branch.json', json_encode( $out ) );
		return $this->dir . '/branch.json';
	}

	/**
	 * Runs the check; returns exit code and all output.
	 *
	 * @param list<string> $args Options.
	 * @return array{0:int, 1:string}
	 */
	private function check( array $args ): array {
		$cmd = array_merge( array( PHP_BINARY, $this->root . 'bin/coverage-check.php', $this->dir . '/clover.xml', '--baseline=' . $this->dir . '/baseline.json' ), $args );
		exec( implode( ' ', array_map( 'escapeshellarg', $cmd ) ) . ' 2>&1', $out, $code );
		return array( $code, implode( "\n", $out ) );
	}

	public function test_a_line_only_run_skips_branch_floors(): void {
		[ $code ] = $this->check( array() );
		$this->assertSame( 0, $code );
		[ $code ] = $this->check( array( '--require=lines' ) );
		$this->assertSame( 0, $code, 'every file has line data' );
	}

	public function test_a_required_branch_report_that_is_missing_fails(): void {
		[ $code, $out ] = $this->check( array( '--require=lines,branches' ) );
		$this->assertSame( 1, $code );
		$this->assertStringContainsString( 'branches: required, but the report is missing or empty', $out );

		[ $code, $out ] = $this->check( array( '--require=lines,branches', '--branches=' . $this->dir . '/none.json' ) );
		$this->assertSame( 1, $code, 'a path to nothing is no report' );

		[ $code, $out ] = $this->check( array( '--require=lines,branches', '--branches=' . $this->branches( array() ) ) );
		$this->assertSame( 1, $code, 'an empty report is no evidence' );
	}

	public function test_a_source_file_the_report_does_not_cover_fails(): void {
		$report         = $this->branches( array( 'src/Unlock/UnlockService.php' => array( 60, 100 ) ) );
		[ $code, $out ] = $this->check( array( '--require=lines,branches', '--branches=' . $report ) );
		$this->assertSame( 1, $code, 'a file never loaded would otherwise drop out of the percentage' );
		$this->assertStringContainsString( 'recovery: branches not measured for 1 file(s): src/Unlock/UnlockForm.php', $out );

		$this->clover( array( 'src/Unlock/UnlockService.php' => array( 90, 100 ) ) );
		[ $code, $out ] = $this->check( array( '--require=lines' ) );
		$this->assertSame( 1, $code );
		$this->assertStringContainsString( 'recovery: lines not measured for 1 file(s): src/Unlock/UnlockForm.php', $out );
	}

	public function test_a_file_listed_as_unmeasured_needs_a_reason_and_is_shown(): void {
		$config               = json_decode( (string) file_get_contents( $this->dir . '/baseline.json' ), true );
		$config['unmeasured'] = array( 'branches' => array( 'src/Unlock/UnlockForm.php' => 'runs only in the test servers' ) );
		file_put_contents( $this->dir . '/baseline.json', json_encode( $config ) );
		$report         = $this->branches( array( 'src/Unlock/UnlockService.php' => array( 60, 100 ) ) );
		[ $code, $out ] = $this->check( array( '--require=lines,branches', '--branches=' . $report ) );
		$this->assertSame( 0, $code );
		$this->assertStringContainsString( 'Not measured (branches): src/Unlock/UnlockForm.php (runs only in the test servers)', $out );
	}

	public function test_floors_still_apply(): void {
		$report         = $this->branches( array( 'src/Unlock/UnlockService.php' => array( 40, 100 ), 'src/Unlock/UnlockForm.php' => array( 4, 4 ) ) );
		[ $code, $out ] = $this->check( array( '--require=lines,branches', '--branches=' . $report ) );
		$this->assertSame( 1, $code );
		$this->assertStringContainsString( 'recovery: 42.3% of branches, below the floor of 50.0%', $out );
		$report  = $this->branches( array( 'src/Unlock/UnlockService.php' => array( 60, 100 ), 'src/Unlock/UnlockForm.php' => array( 4, 4 ) ) );
		[ $code ] = $this->check( array( '--require=lines,branches', '--branches=' . $report ) );
		$this->assertSame( 0, $code );
	}

	public function test_an_unknown_measurement_is_refused(): void {
		[ $code ] = $this->check( array( '--require=paths' ) );
		$this->assertSame( 2, $code );
	}
}
