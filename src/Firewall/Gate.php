<?php
/**
 * Early request gate: allowlist, blocklist and safety exemptions.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Firewall;

use SentinelShield\Feeds\FeedCatalog;
use SentinelShield\Http\Request;
use SentinelShield\Net\IpAddress;
use SentinelShield\Repository\BlockRepository;
use SentinelShield\Repository\EventRepository;
use SentinelShield\Repository\FeedRepository;
use SentinelShield\Safety\SafetyGuard;
use SentinelShield\Settings;
use SentinelShield\Support\Throttle;

defined( 'ABSPATH' ) || exit;

/**
 * Order of checks: emergency/CLI bypass -> server cron exemption -> allowlist -> blocklist
 * -> blocklist feeds (never applied to this server's own IPs).
 * The allowlist always wins, so geo or automatic rules added later can never
 * override an IP the admin explicitly trusts.
 */
final class Gate {

	/**
	 * Most blocked/would-block rows logged per minute across all IPs.
	 */
	public const LOG_BUDGET = 120;

	/**
	 * Block decision deferred to `init` so the unlock flow can use pluggable functions.
	 *
	 * @var Decision|null
	 */
	private ?Decision $deferred = null;

	/**
	 * Constructor.
	 *
	 * @param Settings            $settings Settings.
	 * @param RuleCache           $rules    Compiled rule sets.
	 * @param BlockRepository     $repo     Rule repository.
	 * @param EventRepository     $events   Event log.
	 * @param SafetyGuard         $guard    Safety exemptions.
	 * @param \Closure            $ip       Returns the current client IP.
	 * @param FeedRepository|null $feeds Blocklist feed ranges.
	 * @param \Closure|null       $ip_is_fallback Returns true when the IP is a trusted proxy's own (unusable forwarding header).
	 */
	public function __construct(
		private Settings $settings,
		private RuleCache $rules,
		private BlockRepository $repo,
		private EventRepository $events,
		private SafetyGuard $guard,
		private \Closure $ip,
		private ?FeedRepository $feeds = null,
		private ?\Closure $ip_is_fallback = null
	) {}

	/**
	 * Evaluates an IP and URI.
	 *
	 * @param string $ip               Client IP.
	 * @param string $uri              Request URI.
	 * @param bool   $ignore_allowlist Skip the allowlist (used for "would my IP be blocked?").
	 * @param bool   $simulate         Ignore CLI/emergency bypass (simulator, WP-CLI `check`).
	 */
	public function evaluate( string $ip, string $uri = '/', bool $ignore_allowlist = false, bool $simulate = false ): Decision {
		if ( ! $simulate && $this->guard->is_bypassed() ) {
			return new Decision( Decision::PASS, 'bypass' );
		}
		$bin = IpAddress::to_binary( $ip );
		if ( null === $bin ) {
			return new Decision( Decision::PASS, 'invalid_ip' );
		}
		if ( $this->guard->is_server_cron( $bin, $uri ) ) {
			return new Decision( Decision::PASS, 'server_cron' );
		}
		if ( ! $ignore_allowlist && $this->rules->get( 'allow' )->contains( $bin ) ) {
			return new Decision( Decision::ALLOW, 'allowlist', 'ip_gate' );
		}
		if ( $this->rules->get( 'block' )->contains( $bin ) ) {
			$rule = $this->repo->find_containing( 'block', $bin )[0] ?? null;
			if ( null === $rule ) {
				// The cache is stale (rule deleted or expired). Self-heal and let the request through.
				$this->rules->flush();
				return new Decision( Decision::PASS, 'stale_cache' );
			}
			return new Decision( Decision::BLOCK, (string) $rule['reason'], 'ip_gate', $rule );
		}
		return $this->evaluate_feeds( $bin ) ?? new Decision( Decision::PASS );
	}

	/**
	 * Blocklist feed check. Several feeds may list the same address; all are named.
	 *
	 * @param string $bin Packed address.
	 */
	private function evaluate_feeds( string $bin ): ?Decision {
		if ( null === $this->feeds || ! $this->settings->is_module_enabled( 'feeds' ) ) {
			return null;
		}
		$slugs = FeedCatalog::enabled_slugs( $this->settings );
		if ( ! $slugs || ! $this->rules->feeds( $slugs )->contains( $bin ) || $this->guard->is_server_ip( $bin ) ) {
			return null;
		}
		$rows = $this->feeds->find_containing( $bin, $slugs );
		if ( ! $rows ) {
			$this->rules->flush_feeds();
			return new Decision( Decision::PASS, 'stale_cache' );
		}
		$listed = array_values( array_unique( array_column( $rows, 'feed' ) ) );
		$names  = array_map( static fn( string $slug ): string => FeedCatalog::NAMES[ $slug ] ?? $slug, $listed );
		$start  = IpAddress::from_binary( (string) hex2bin( (string) $rows[0]['start_hex'] ) );
		$reason = 'Blocklist: ' . implode( ', ', $names );
		return new Decision(
			Decision::BLOCK,
			$reason,
			'ip_gate',
			array(
				'id'     => 0,
				'label'  => $start . '/' . (int) $rows[0]['prefix'],
				'reason' => $reason,
				'source' => 'feed',
				'feeds'  => $listed,
			)
		);
	}

	/**
	 * Whether an IP may never be locked out (allowlisted or this server).
	 *
	 * With $login, for login limits and location rules: automatic administrator
	 * allowlist entries do not count there. They exist so an administrator is
	 * never blocked from the site; they should not exempt everyone else behind
	 * the same office, VPN or public Wi-Fi address from login protection.
	 *
	 * @param string $ip    IP text.
	 * @param bool   $login Checking a login exemption.
	 */
	public function is_protected( string $ip, bool $login = false ): bool {
		$bin = IpAddress::to_binary( $ip );
		if ( null === $bin ) {
			return true;
		}
		return $this->guard->is_server_ip( $bin ) || $this->rules->get( $login ? 'allow_login' : 'allow' )->contains( $bin );
	}

	/**
	 * Whether test mode suppresses enforcement of a rule from the given source.
	 *
	 * @param string $source Rule source.
	 */
	public function is_test_for_source( string $source ): bool {
		if ( 'feed' === $source ) {
			return $this->settings->is_test_mode_chain( 'feeds', 'ip_gate' );
		}
		if ( ! $this->settings->is_test_mode( 'ip_gate' ) ) {
			return false;
		}
		if ( 'automatic' === $this->settings->get( 'general.test_mode_scope' ) && in_array( $source, BlockRepository::MANUAL_SOURCES, true ) ) {
			return false;
		}
		return true;
	}

	/**
	 * Enforces the decision for the current request. Called while plugins load.
	 */
	public function enforce(): void {
		$ip  = ( $this->ip )();
		$uri = Request::uri();
		// A request that fell back to a trusted proxy's own IP is anonymous: it must not
		// inherit an allowlist entry that covers the proxy (or loopback).
		$fallback = null !== $this->ip_is_fallback && ( $this->ip_is_fallback )();
		$decision = $this->evaluate( $ip, $uri, $fallback );
		if ( ! $decision->is_block() ) {
			return;
		}
		$rule = (array) $decision->rule;
		$test = $this->is_test_for_source( (string) ( $rule['source'] ?? 'manual' ) );

		if ( ! empty( $rule['id'] ) ) {
			$this->repo->increment_hits( (int) $rule['id'] );
		}
		$event = $test ? 'would_block' : 'blocked';
		// One row per IP per minute, and at most LOG_BUDGET rows per minute site-wide,
		// so an attack (even from many IPs) cannot grow the event table without bound.
		if ( Throttle::once_within_budget( 'evt_' . $event . '_' . md5( $ip ), MINUTE_IN_SECONDS, 'evt_blocked_all', self::LOG_BUDGET, MINUTE_IN_SECONDS ) ) {
			$this->events->log(
				$event,
				array(
					'ip'         => $ip,
					'module'     => 'ip_gate',
					'reason'     => $decision->reason,
					'uri'        => $uri,
					'user_agent' => Request::user_agent(),
					'is_test'    => $test,
					'context'    => array(
						'rule_id' => (int) ( $rule['id'] ?? 0 ),
						'rule'    => (string) ( $rule['label'] ?? '' ),
						'source'  => (string) ( $rule['source'] ?? '' ),
					),
				)
			);
		}
		if ( $test ) {
			return;
		}

		if ( $this->is_unlock_request() && $this->settings->is_module_enabled( 'unlock' ) && '403' === $this->settings->get( 'general.block_response' ) ) {
			// The unlock flow needs wp_mail()/get_user_by(), which load after plugins.
			// UnlockService handles this at init priority 0 and exits; priority 1 is a fail-closed fallback.
			$this->deferred = $decision;
			add_action(
				'init',
				function () use ( $decision, $ip ): void {
					BlockPage::send( $decision, $this->settings, $ip );
				},
				1
			);
			return;
		}
		BlockPage::send( $decision, $this->settings, $ip );
	}

	/**
	 * The deferred block decision, if any.
	 */
	public function deferred(): ?Decision {
		return $this->deferred;
	}

	/**
	 * Whether this request is part of the unlock flow.
	 */
	private function is_unlock_request(): bool {
		// phpcs:disable WordPress.Security.NonceVerification -- Presence check only; UnlockService verifies an HMAC form token.
		return isset( $_GET['sentinel_unlock'] ) || isset( $_POST['sentinel_unlock_request'] );
		// phpcs:enable
	}
}
