<?php
/**
 * Keeps administrators from locking themselves out.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Safety;

use SentinelShield\Firewall\Decision;
use SentinelShield\Firewall\Gate;
use SentinelShield\Firewall\RuleCache;
use SentinelShield\Net\Cidr;
use SentinelShield\Net\IpAddress;
use SentinelShield\Repository\BlockRepository;
use SentinelShield\Repository\EventRepository;
use SentinelShield\Support\Throttle;

defined( 'ABSPATH' ) || exit;

/**
 * Auto-allowlists the saving admin's IP and reports when that IP matches a block rule.
 */
final class AdminProtection {

	/**
	 * Constructor.
	 *
	 * @param BlockRepository $repo   Rules.
	 * @param RuleCache       $cache  Cache.
	 * @param Gate            $gate   Gate.
	 * @param EventRepository $events Event log.
	 */
	public function __construct(
		private BlockRepository $repo,
		private RuleCache $cache,
		private Gate $gate,
		private EventRepository $events
	) {}

	/**
	 * Allowlists the IP if it is not already covered: for $days days (renewed
	 * while administrators keep using it, see renew()), or permanently with 0.
	 * Home and office IPs change and get reassigned, so an entry nobody uses
	 * any more should not trust its next owner forever.
	 *
	 * @param string $ip      Admin IP.
	 * @param int    $user_id Admin user ID.
	 * @param int    $days    Days the entry lasts without use (0 = permanent).
	 * @return bool True when a new entry was added.
	 */
	public function ensure_allowlisted( string $ip, int $user_id, int $days = 0 ): bool {
		$cidr = Cidr::parse( $ip );
		if ( null === $cidr ) {
			return false;
		}
		if ( $this->renew( $ip, $days, true ) || $this->cache->get( 'allow' )->contains( $cidr->start ) ) {
			return false;
		}
		$this->repo->add(
			'allow',
			$cidr,
			/* translators: %d: user ID. */
			sprintf( __( 'Administrator IP, auto-allowlisted when settings were saved (user #%d)', 'sentinel-shield' ), $user_id ),
			'admin_auto',
			$days > 0 ? time() + $days * DAY_IN_SECONDS : null,
			$user_id
		);
		$this->cache->flush();
		$this->events->log(
			'allowlist_auto',
			array(
				'ip'      => $ip,
				'module'  => 'core',
				'reason'  => 'Administrator IP auto-allowlisted',
				'user_id' => $user_id,
			)
		);
		return true;
	}

	/**
	 * Pushes back the expiry of the IP's automatic allowlist entry (only an
	 * entry this plugin added for an administrator; manual entries are never
	 * touched). Throttled to one write per IP per day unless $force.
	 *
	 * @param string $ip    Admin IP.
	 * @param int    $days  Days from now (0 = make it permanent).
	 * @param bool   $force Skip the daily throttle.
	 * @return bool True when the IP has an automatic entry (renewed or not).
	 */
	public function renew( string $ip, int $days, bool $force = false ): bool {
		if ( ! $force && ! Throttle::once( 'admin_allow_renew_' . md5( $ip ), DAY_IN_SECONDS ) ) {
			return false;
		}
		$cidr = Cidr::parse( $ip );
		$row  = null === $cidr ? null : $this->repo->find_exact( 'allow', $cidr );
		if ( null === $cidr || null === $row || 'admin_auto' !== $row['source'] ) {
			return false;
		}
		// 0 days: the entry becomes permanent again. Otherwise push the expiry back.
		$until = $days > 0 ? time() + $days * DAY_IN_SECONDS : null;
		$stale = null === $until ? null !== $row['expires_at'] : ( null !== $row['expires_at'] && strtotime( $row['expires_at'] . ' UTC' ) < $until - HOUR_IN_SECONDS );
		if ( $stale ) {
			$this->repo->add( 'allow', $cidr, (string) $row['reason'], 'admin_auto', $until, (int) $row['created_by'] );
			$this->cache->flush();
		}
		return true;
	}

	/**
	 * The block that would apply to this IP if it were not allowlisted, or null.
	 *
	 * @param string $ip IP.
	 */
	public function self_check( string $ip ): ?Decision {
		$decision = $this->gate->evaluate( $ip, '/wp-admin/', true, true );
		return $decision->is_block() ? $decision : null;
	}

	/**
	 * Whether detected request details identify a real client worth auto-allowlisting.
	 *
	 * Loopback and trusted-proxy addresses are what a misconfigured proxy setup reports
	 * for every visitor; allowlisting them would exempt the whole site.
	 *
	 * @param array<string, mixed> $details ClientIp::details() output.
	 */
	public static function is_real_client( array $details ): bool {
		$bin = IpAddress::to_binary( (string) ( $details['ip'] ?? '' ) );
		if ( null === $bin || ! empty( $details['fallback'] ) ) {
			return false;
		}
		if ( ! empty( $details['remote_trusted'] ) && $details['ip'] === $details['remote_addr'] ) {
			return false;
		}
		return ! Cidr::parse( '127.0.0.0/8' )->contains( $bin ) && '::1' !== IpAddress::from_binary( $bin );
	}

	/**
	 * Whether adding this block range would cover the admin's own IP.
	 *
	 * @param Cidr   $cidr     Range to block.
	 * @param string $admin_ip Admin IP.
	 */
	public static function covers( Cidr $cidr, string $admin_ip ): bool {
		$admin = Cidr::parse( $admin_ip );
		return null !== $admin && $cidr->contains( $admin->start );
	}
}
