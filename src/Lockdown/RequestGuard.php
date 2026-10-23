<?php
/**
 * Refuses requests that carry the markers of recent attacks.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Lockdown;

use SentinelShield\Firewall\Gate;
use SentinelShield\Http\Request;
use SentinelShield\Repository\EventRepository;
use SentinelShield\Settings;
use SentinelShield\Support\Throttle;

defined( 'ABSPATH' ) || exit;

/**
 * Runs while Sentinel Shield's plugin file loads, before plugins that sort
 * after it (UpdraftPlus among them) and before any plugin's init hooks, which is
 * where the UpdraftCentral backdoors read their trigger parameter. A backdoor
 * that acts as soon as its own file loads is not stopped by this; the scan
 * finds it.
 *
 * PHP2Shell runs while PHP reads the request, before any PHP code: a malformed
 * session cookie is refused and logged so the probe is seen, but only updating
 * PHP prevents the attack.
 */
final class RequestGuard {

	/**
	 * Constructor.
	 *
	 * @param Settings        $settings Settings.
	 * @param EventRepository $events   Event log.
	 * @param \Closure        $bypassed Returns true for WP-CLI and the emergency switch.
	 * @param Gate            $gate     Allowlist lookups.
	 * @param \Closure        $ip       Returns the client IP.
	 * @param \Closure|null   $respond  Sends the refusal (default: 403 and exit).
	 */
	public function __construct(
		private Settings $settings,
		private EventRepository $events,
		private \Closure $bypassed,
		private Gate $gate,
		private \Closure $ip,
		private ?\Closure $respond = null
	) {}

	/**
	 * Why a request should be refused, or null.
	 *
	 * @param array<string, mixed> $get     Query parameters.
	 * @param array<string, mixed> $post    Form fields.
	 * @param array<string, mixed> $cookies Cookies.
	 * @param string               $ip      Client IP.
	 */
	public function decide( array $get, array $post, array $cookies, string $ip ): ?string {
		if ( $this->settings->get( 'lockdown.block_indicators', true ) ) {
			$why = Advisories::request_match( $get, $cookies );
			if ( null !== $why ) {
				return $why;
			}
			// The campaign addresses may be shared (VPN exits): an allowlist entry wins.
			if ( Advisories::is_attack_ip( $ip ) && ! $this->gate->is_protected( $ip ) ) {
				return 'address used by the UpdraftCentral backdoor campaign';
			}
		}
		if ( $this->settings->get( 'lockdown.block_updraftcentral', false ) && self::is_updraftcentral( $post ) ) {
			return 'UpdraftCentral remote command (refused by setting)';
		}
		return null;
	}

	/**
	 * Whether a request is an UpdraftCentral remote command.
	 *
	 * @param array<string, mixed> $post Form fields.
	 */
	public static function is_updraftcentral( array $post ): bool {
		return isset( $post['udrpc_message'] );
	}

	/**
	 * Checks the current request.
	 */
	public function enforce(): void {
		if ( ( $this->bypassed )() ) {
			return;
		}
		$ip = ( $this->ip )();
		// phpcs:disable WordPress.Security.NonceVerification -- Only looks for attack markers; nothing is processed.
		$why = $this->decide( (array) $_GET, (array) $_POST, (array) $_COOKIE, $ip );
		// phpcs:enable
		if ( null === $why ) {
			return;
		}
		if ( Throttle::once_within_budget( 'evt_indicator_' . md5( $ip . $why ), MINUTE_IN_SECONDS, 'evt_indicator_all', 60, MINUTE_IN_SECONDS ) ) {
			$this->events->log(
				'lockdown_request',
				array(
					'ip'         => $ip,
					'module'     => 'lockdown',
					'reason'     => $why,
					'uri'        => Request::uri(),
					'user_agent' => Request::user_agent(),
				)
			);
		}
		if ( null !== $this->respond ) {
			( $this->respond )( $why );
			return;
		}
		if ( ! headers_sent() ) {
			status_header( 403 );
			nocache_headers();
			header( 'Content-Type: text/plain; charset=utf-8' );
		}
		echo 'Forbidden';
		exit;
	}
}
