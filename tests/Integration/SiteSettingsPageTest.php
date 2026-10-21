<?php
/**
 * The per-site settings page on multisite.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Tests\Integration;

use SentinelShield\Admin\SiteSettingsPage;
use SentinelShield\Plugin;
use SentinelShield\Settings;
use SentinelShield\SettingsSchema;

/**
 * Found by the required-coverage check (review 6): no test loaded this page.
 * A site administrator sees only the settings a site may override, with the
 * network value until overridden; anyone else is turned away.
 */
final class SiteSettingsPageTest extends \WP_UnitTestCase {

	public function set_up(): void {
		parent::set_up();
		if ( ! is_multisite() ) {
			$this->markTestSkipped( 'Multisite only.' );
		}
	}

	private function render(): string {
		ob_start();
		try {
			( new SiteSettingsPage( Plugin::instance()->container() ) )->render();
		} finally {
			$html = (string) ob_get_clean();
		}
		return $html;
	}

	public function test_a_site_administrator_sees_only_what_a_site_may_override(): void {
		$site  = self::factory()->blog->create();
		$admin = self::factory()->user->create();
		add_user_to_blog( $site, $admin, 'administrator' );
		switch_to_blog( $site );
		wp_set_current_user( $admin );
		try {
			$html = $this->render();
		} finally {
			restore_current_blog();
		}
		$this->assertStringContainsString( 'Sentinel Shield: Site Settings', $html );
		$this->assertStringContainsString( 'name="_wpnonce"', $html, 'the form carries a nonce' );
		$this->assertNotEmpty( Settings::OVERRIDABLE );
		foreach ( Settings::OVERRIDABLE as $key ) {
			$this->assertStringContainsString( 'name="sentinel_override[' . $key . ']"', $html );
			$this->assertStringContainsString( esc_html( (string) SettingsSchema::field( $key )['label'] ), $html );
		}
		$this->assertSame( count( Settings::OVERRIDABLE ), substr_count( $html, 'name="sentinel_override[' ), 'nothing else: IP rules stay network-wide' );
		$this->assertStringNotContainsString( 'checked=', explode( 'name="sentinel_override[', $html )[1] ?? '', 'not overridden yet' );
	}

	public function test_anyone_else_is_turned_away(): void {
		$site = self::factory()->blog->create();
		$user = self::factory()->user->create();
		add_user_to_blog( $site, $user, 'editor' );
		switch_to_blog( $site );
		wp_set_current_user( $user );
		try {
			$this->expectException( \WPDieException::class );
			$this->render();
		} finally {
			restore_current_blog();
		}
	}
}
