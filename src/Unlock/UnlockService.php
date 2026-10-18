<?php
/**
 * Emailed one-time unlock links for locked-out administrators.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Unlock;

use SentinelShield\Firewall\BlockPage;
use SentinelShield\Firewall\Gate;
use SentinelShield\Lockout\Unblocker;
use SentinelShield\Repository\EventRepository;
use SentinelShield\Repository\TokenRepository;
use SentinelShield\Settings;
use SentinelShield\Support\Mutex;
use SentinelShield\Support\Throttle;

defined( 'ABSPATH' ) || exit;

/**
 * Flow: blocked admin submits email on the block page -> if it belongs to an
 * administrator, a 64-hex token (stored hashed) is emailed -> following the link
 * removes the IP's single-IP blocks and temporarily allowlists it.
 * Responses never reveal whether an email address belongs to an account.
 *
 * Limits (checked under one database lock, so parallel requests cannot slip
 * past them): requests per IP per hour (setting), and per account a cooldown
 * between emails, a cap per hour and on unused links, plus a site-wide cap
 * per hour. A request over an account or site limit gets the same generic
 * answer and no email. A link only works while its account may still unlock;
 * links are invalidated when the account is deleted or loses that right.
 */
final class UnlockService {

	public const ACCOUNT_COOLDOWN = 300;
	public const ACCOUNT_PER_HOUR = 3;
	public const ACCOUNT_OPEN     = 2;
	public const SITE_PER_HOUR    = 10;

	/**
	 * Constructor.
	 *
	 * @param Settings        $settings  Settings.
	 * @param TokenRepository $tokens    Tokens.
	 * @param Unblocker       $unblocker Unblocker.
	 * @param EventRepository $events    Event log.
	 * @param Gate            $gate      Gate.
	 * @param \Closure        $ip        Returns the current client IP.
	 */
	public function __construct(
		private Settings $settings,
		private TokenRepository $tokens,
		private Unblocker $unblocker,
		private EventRepository $events,
		private Gate $gate,
		private \Closure $ip
	) {}

	/**
	 * Hooks the handler.
	 */
	public function register(): void {
		add_action( 'init', array( $this, 'on_init' ), 0 );
		add_action( 'deleted_user', array( $this, 'revoke_if_needed' ) );
		add_action( 'set_user_role', array( $this, 'revoke_if_needed' ) );
		add_action( 'remove_user_role', array( $this, 'revoke_if_needed' ) );
		add_action( 'revoked_super_admin', array( $this, 'revoke_if_needed' ) );
	}

	/**
	 * Invalidates an account's unused links when it no longer exists or may no
	 * longer unlock.
	 *
	 * @param int|string $user_id Account.
	 */
	public function revoke_if_needed( $user_id ): void {
		$user = get_userdata( (int) $user_id );
		if ( $user instanceof \WP_User && self::can_unlock( $user ) ) {
			return;
		}
		if ( $this->tokens->revoke_user( (int) $user_id ) > 0 ) {
			$this->events->log(
				'unlock_revoked',
				array(
					'module'  => 'unlock',
					'reason'  => __( 'Unused unlock links invalidated: the account was deleted or can no longer unlock', 'sentinel-shield' ),
					'user_id' => (int) $user_id,
				)
			);
		}
	}

	/**
	 * Handles unlock links and deferred unlock form submissions.
	 */
	public function on_init(): void {
		// phpcs:disable WordPress.Security.NonceVerification -- Token-authenticated (link) or HMAC-authenticated (form).
		if ( isset( $_GET['sentinel_unlock'] ) ) {
			$this->handle_link( sanitize_text_field( wp_unslash( $_GET['sentinel_unlock'] ) ) );
		}
		$deferred = $this->gate->deferred();
		if ( null !== $deferred && isset( $_POST['sentinel_unlock_request'] ) ) {
			BlockPage::send( $deferred, $this->settings, ( $this->ip )(), $this->handle_request() );
		}
		// phpcs:enable
	}

	/**
	 * Processes the email form. Returns the notice to show.
	 */
	private function handle_request(): string {
		// phpcs:disable WordPress.Security.NonceVerification.Missing -- Verified by UnlockForm::verify().
		$ip      = ( $this->ip )();
		$generic = sprintf(
			/* translators: %d: minutes. */
			__( 'If that address belongs to a site administrator, an unlock link has been sent. It expires in %d minutes.', 'sentinel-shield' ),
			(int) $this->settings->get( 'unlock.token_ttl_minutes', 30 )
		);
		$token = isset( $_POST['sentinel_token'] ) ? sanitize_text_field( wp_unslash( $_POST['sentinel_token'] ) ) : '';
		if ( ! UnlockForm::verify( $token, $ip ) ) {
			return __( 'The form expired. Reload the page and try again.', 'sentinel-shield' );
		}
		if ( ! empty( $_POST['sentinel_website'] ) ) {
			return $generic;
		}
		$email = isset( $_POST['sentinel_email'] ) ? sanitize_email( wp_unslash( $_POST['sentinel_email'] ) ) : '';
		// phpcs:enable
		return (string) Mutex::run(
			'unlock_request',
			5,
			fn(): string => $this->request_locked( $ip, $email, $generic ),
			__( 'The site is busy. Please try again in a minute.', 'sentinel-shield' )
		);
	}

	/**
	 * The rate-limited part of handle_request(), run under the unlock lock.
	 *
	 * @param string $ip      Requesting IP.
	 * @param string $email   Submitted address.
	 * @param string $generic Generic answer.
	 */
	private function request_locked( string $ip, string $email, string $generic ): string {
		$rate_key = 'sentinel_shield_unlock_rl_' . md5( $ip );
		$count    = (int) get_site_transient( $rate_key );
		if ( $count >= (int) $this->settings->get( 'unlock.max_requests_per_hour', 3 ) ) {
			return __( 'Too many unlock requests from your IP. Try again in an hour.', 'sentinel-shield' );
		}
		set_site_transient( $rate_key, $count + 1, HOUR_IN_SECONDS );

		$user = '' === $email ? false : get_user_by( 'email', $email );
		if ( ! $user instanceof \WP_User || ! self::can_unlock( $user ) ) {
			return $generic;
		}
		$limit = $this->over_limit( (int) $user->ID );
		if ( null !== $limit ) {
			if ( Throttle::once( 'unlock_limited_' . $user->ID . '_' . $limit, 10 * MINUTE_IN_SECONDS ) ) {
				$this->events->log(
					'unlock_limited',
					array(
						'ip'      => $ip,
						'module'  => 'unlock',
						/* translators: %s: which limit. */
						'reason'  => sprintf( __( 'Unlock email not sent (%s)', 'sentinel-shield' ), $limit ),
						'user_id' => (int) $user->ID,
					)
				);
			}
			return $generic;
		}
		$this->send_link( $user, $ip );
		return $generic;
	}

	/**
	 * Which account or site limit an unlock email would break, or null.
	 *
	 * @param int $user_id Account.
	 */
	private function over_limit( int $user_id ): ?string {
		$now = time();
		if ( $now - $this->tokens->last_created( $user_id ) < self::ACCOUNT_COOLDOWN ) {
			/* translators: %d: minutes. */
			return sprintf( __( 'one per account every %d minutes', 'sentinel-shield' ), self::ACCOUNT_COOLDOWN / MINUTE_IN_SECONDS );
		}
		if ( $this->tokens->count_created( $now - HOUR_IN_SECONDS, $user_id ) >= self::ACCOUNT_PER_HOUR ) {
			/* translators: %d: count. */
			return sprintf( __( '%d per account per hour', 'sentinel-shield' ), self::ACCOUNT_PER_HOUR );
		}
		if ( $this->tokens->count_outstanding( $user_id ) >= self::ACCOUNT_OPEN ) {
			/* translators: %d: count. */
			return sprintf( __( 'the account already has %d unused links', 'sentinel-shield' ), self::ACCOUNT_OPEN );
		}
		if ( $this->tokens->count_created( $now - HOUR_IN_SECONDS ) >= self::SITE_PER_HOUR ) {
			/* translators: %d: count. */
			return sprintf( __( '%d per site per hour', 'sentinel-shield' ), self::SITE_PER_HOUR );
		}
		return null;
	}

	/**
	 * Emails a fresh link and returns it (WP-CLI uses the return value).
	 *
	 * @param \WP_User $user  Administrator.
	 * @param string   $ip    IP that requested the unlock.
	 * @param bool     $email Whether to send the email.
	 */
	public function send_link( \WP_User $user, string $ip, bool $email = true ): string {
		$ttl   = (int) $this->settings->get( 'unlock.token_ttl_minutes', 30 );
		$token = $this->tokens->create( (int) $user->ID, $ip, $ttl * MINUTE_IN_SECONDS );
		$url   = add_query_arg( 'sentinel_unlock', $token, home_url( '/' ) );
		$this->events->log(
			'unlock_requested',
			array(
				'ip'      => $ip,
				'module'  => 'unlock',
				'reason'  => $email ? 'email' : 'cli',
				'user_id' => (int) $user->ID,
			)
		);
		if ( $email ) {
			$site = wp_specialchars_decode( (string) get_bloginfo( 'name' ), ENT_QUOTES );
			/* translators: %s: site name. */
			$subject = sprintf( __( '[%s] Your Sentinel Shield unlock link', 'sentinel-shield' ), $site );
			$body    = sprintf(
				/* translators: 1: IP address, 2: unlock URL, 3: minutes. */
				__( "Someone (hopefully you) asked to unlock the IP address %1\$s on this site.\n\nOpen this link to review and confirm the unlock:\n%2\$s\n\nThe link works once and expires in %3\$d minutes. If you did not request this, ignore this email; nothing will change.", 'sentinel-shield' ),
				$ip,
				$url,
				$ttl
			);
			wp_mail( $user->user_email, $subject, $body );
		}
		return $url;
	}

	/**
	 * Consumes a link token.
	 *
	 * @param string $token Token from the URL.
	 */
	private function handle_link( string $token ): void {
		$token   = strtolower( $token );
		$valid   = 1 === preg_match( '/^[a-f0-9]{64}$/', $token );
		$confirm = isset( $_POST['sentinel_unlock_confirm'] ); // phpcs:ignore WordPress.Security.NonceVerification.Missing -- The secret link token authenticates the request.
		$row     = $valid ? $this->tokens->peek( $token ) : null;
		if ( null !== $row && ! $this->account_may_unlock( (int) $row['user_id'] ) ) {
			// Deleted or demoted since the link was sent: the link dies with the right to unlock.
			$this->tokens->revoke_user( (int) $row['user_id'] );
			$this->events->log(
				'unlock_refused',
				array(
					'ip'      => ( $this->ip )(),
					'module'  => 'unlock',
					'reason'  => __( 'Unlock link refused: its account was deleted or can no longer unlock', 'sentinel-shield' ),
					'user_id' => (int) $row['user_id'],
				)
			);
			$row = null;
		}
		if ( null !== $row && $confirm ) {
			$row = $this->tokens->consume( $token );
		}
		if ( null === $row ) {
			$message  = __( 'This unlock link is invalid, has already been used, or has expired.', 'sentinel-shield' );
			$deferred = $this->gate->deferred();
			if ( null !== $deferred ) {
				BlockPage::send( $deferred, $this->settings, ( $this->ip )(), $message );
			}
			wp_die( esc_html( $message ), esc_html__( 'Unlock failed', 'sentinel-shield' ), array( 'response' => 403 ) );
		}
		$current   = ( $this->ip )();
		$requester = (string) $row['ip_text'];
		if ( ! $confirm ) {
			// Opening the link only shows what would happen; a POST is needed to act.
			if ( ! headers_sent() ) {
				status_header( 200 );
				nocache_headers();
				header( 'Content-Type: text/html; charset=utf-8' );
				header( 'X-Robots-Tag: noindex, nofollow' );
				header( 'Referrer-Policy: no-referrer' );
			}
			echo BlockPage::unlock_confirm( $requester, $current, add_query_arg( 'sentinel_unlock', $token, home_url( '/' ) ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- unlock_confirm() escapes every value.
			exit;
		}
		$hours = (int) $this->settings->get( 'unlock.allow_hours', 24 );
		$ips   = array( $current );
		if ( $requester === $current || ! empty( $_POST['sentinel_unlock_requester'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing -- See above.
			$ips[] = $requester;
		}
		foreach ( array_unique( array_filter( $ips ) ) as $ip ) {
			$this->unblocker->unblock( $ip, false, $hours, (int) $row['user_id'], 'email_link' );
		}
		wp_safe_redirect( add_query_arg( 'sentinel_unlocked', '1', wp_login_url() ) );
		exit;
	}

	/**
	 * Whether the account behind a link still exists and may unlock.
	 *
	 * @param int $user_id Account.
	 */
	private function account_may_unlock( int $user_id ): bool {
		clean_user_cache( $user_id );
		$user = get_userdata( $user_id );
		return $user instanceof \WP_User && self::can_unlock( $user );
	}

	/**
	 * Only administrators (super admins on multisite) may unlock.
	 *
	 * @param \WP_User $user User.
	 */
	public static function can_unlock( \WP_User $user ): bool {
		return is_multisite() ? is_super_admin( $user->ID ) : user_can( $user, 'manage_options' );
	}
}
