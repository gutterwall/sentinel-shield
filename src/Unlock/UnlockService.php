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

defined( 'ABSPATH' ) || exit;

/**
 * Flow: blocked admin submits email on the block page -> if it belongs to an
 * administrator, a 64-hex token (stored hashed) is emailed -> following the link
 * removes the IP's single-IP blocks and temporarily allowlists it.
 * Responses never reveal whether an email address belongs to an account.
 */
final class UnlockService {

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
		$rate_key = 'sentinel_shield_unlock_rl_' . md5( $ip );
		$count    = (int) get_site_transient( $rate_key );
		if ( $count >= (int) $this->settings->get( 'unlock.max_requests_per_hour', 3 ) ) {
			return __( 'Too many unlock requests from your IP. Try again in an hour.', 'sentinel-shield' );
		}
		set_site_transient( $rate_key, $count + 1, HOUR_IN_SECONDS );

		$email = isset( $_POST['sentinel_email'] ) ? sanitize_email( wp_unslash( $_POST['sentinel_email'] ) ) : '';
		// phpcs:enable
		$user = '' === $email ? false : get_user_by( 'email', $email );
		if ( $user instanceof \WP_User && self::can_unlock( $user ) ) {
			$this->send_link( $user, $ip );
		}
		return $generic;
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
				__( "Someone (hopefully you) asked to unlock the IP address %1\$s on this site.\n\nOpen this link to remove the block and temporarily allowlist your IP:\n%2\$s\n\nThe link works once and expires in %3\$d minutes. If you did not request this, ignore this email; nothing will change.", 'sentinel-shield' ),
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
		$token = strtolower( $token );
		$row   = preg_match( '/^[a-f0-9]{64}$/', $token ) ? $this->tokens->consume( $token ) : null;
		if ( null === $row ) {
			$message  = __( 'This unlock link is invalid, has already been used, or has expired.', 'sentinel-shield' );
			$deferred = $this->gate->deferred();
			if ( null !== $deferred ) {
				BlockPage::send( $deferred, $this->settings, ( $this->ip )(), $message );
			}
			wp_die( esc_html( $message ), esc_html__( 'Unlock failed', 'sentinel-shield' ), array( 'response' => 403 ) );
		}
		$hours = (int) $this->settings->get( 'unlock.allow_hours', 24 );
		$ips   = array_unique( array_filter( array( ( $this->ip )(), (string) $row['ip_text'] ) ) );
		foreach ( $ips as $ip ) {
			$this->unblocker->unblock( $ip, false, $hours, (int) $row['user_id'], 'email_link' );
		}
		wp_safe_redirect( add_query_arg( 'sentinel_unlocked', '1', wp_login_url() ) );
		exit;
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
