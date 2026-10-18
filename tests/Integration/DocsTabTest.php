<?php
/**
 * Documentation tab: covers every setting, shows approvals, has no save form;
 * readme.txt settings reference matches the schema.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Tests\Integration;

use SentinelShield\Admin\SettingsPage;
use SentinelShield\Lockdown\AdminRegistry;
use SentinelShield\Plugin;
use SentinelShield\SettingsSchema;

final class DocsTabTest extends \WP_UnitTestCase {

	use AdminUsers;

	public function tear_down(): void {
		delete_site_option( AdminRegistry::OPTION );
		unset( $_GET['tab'] );
		parent::tear_down();
	}

	private function render(): string {
		$admin = self::create_admin( array( 'user_login' => 'docs_admin' ) );
		wp_set_current_user( $admin );
		Plugin::instance()->container()->get( AdminRegistry::class )->approve( $admin, $admin );
		$_GET['tab'] = 'docs';
		ob_start();
		( new SettingsPage( Plugin::instance()->container() ) )->render();
		return (string) ob_get_clean();
	}

	public function test_lists_every_setting_and_the_approvals(): void {
		$html = $this->render();
		foreach ( SettingsSchema::fields() as $field ) {
			$this->assertStringContainsString( '<code>' . esc_html( $field['key'] ) . '</code>', $html, $field['key'] . ' is missing from the Documentation tab' );
		}
		$this->assertStringContainsString( 'id="ss-doc-admins"', $html );
		$this->assertStringContainsString( 'docs_admin', $html );
		$this->assertStringNotContainsString( 'Save settings', $html );
	}

	public function test_readme_reference_is_current(): void {
		exec( escapeshellarg( PHP_BINARY ) . ' ' . escapeshellarg( dirname( __DIR__, 2 ) . '/bin/readme-settings.php' ) . ' --check 2>&1', $out, $code );
		$this->assertSame( 0, $code, implode( "\n", $out ) );
	}
}
