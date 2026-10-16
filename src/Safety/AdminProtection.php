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
use SentinelShield\Repository\BlockRepository;
use SentinelShield\Repository\EventRepository;

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
	 * Adds the IP to the permanent allowlist if it is not already covered.
	 *
	 * @param string $ip      Admin IP.
	 * @param int    $user_id Admin user ID.
	 * @return bool True when a new entry was added.
	 */
	public function ensure_allowlisted( string $ip, int $user_id ): bool {
		$cidr = Cidr::parse( $ip );
		if ( null === $cidr || $this->cache->get( 'allow' )->contains( $cidr->start ) ) {
			return false;
		}
		$this->repo->add(
			'allow',
			$cidr,
			/* translators: %d: user ID. */
			sprintf( __( 'Administrator IP, auto-allowlisted when settings were saved (user #%d)', 'sentinel-shield' ), $user_id ),
			'admin_auto',
			null,
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
	 * The block that would apply to this IP if it were not allowlisted, or null.
	 *
	 * @param string $ip IP.
	 */
	public function self_check( string $ip ): ?Decision {
		$decision = $this->gate->evaluate( $ip, '/wp-admin/', true, true );
		return $decision->is_block() ? $decision : null;
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
