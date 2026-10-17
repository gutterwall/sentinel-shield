<?php
/**
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SentinelShield\Http\Request;

final class RequestTest extends TestCase {

	public function test_redacts_unlock_token(): void {
		$this->assertSame( '/?sentinel_unlock=[redacted]', Request::redact_uri( '/?sentinel_unlock=3fde87a599a975a1' ) );
	}

	public function test_redacts_token_among_other_params(): void {
		$this->assertSame(
			'/page/?a=1&sentinel_unlock=[redacted]&b=2#top',
			Request::redact_uri( '/page/?a=1&sentinel_unlock=abc123&b=2#top' )
		);
	}

	public function test_leaves_other_uris_alone(): void {
		$this->assertSame( '/wp-login.php?sentinel_unlocked=1', Request::redact_uri( '/wp-login.php?sentinel_unlocked=1' ) );
		$this->assertSame( '/?s=sentinel_unlock=x', Request::redact_uri( '/?s=sentinel_unlock=x' ) );
	}
}
