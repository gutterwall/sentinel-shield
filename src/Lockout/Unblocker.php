<?php
/**
 * Removes blocks for an IP (admin UI, WP-CLI, unlock links).
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Lockout;

use SentinelShield\Firewall\RuleCache;
use SentinelShield\Net\Cidr;
use SentinelShield\Repository\BlockRepository;
use SentinelShield\Repository\EventRepository;
use SentinelShield\Repository\OffenseRepository;

defined( 'ABSPATH' ) || exit;

/**
 * Single-IP blocks are deleted. Range blocks containing the IP are only deleted
 * when asked, because they may cover other attackers; a temporary allowlist entry
 * is the safer way to let one IP through a range.
 */
final class Unblocker {

	/**
	 * Constructor.
	 *
	 * @param BlockRepository   $repo     Rules.
	 * @param RuleCache         $cache    Cache.
	 * @param OffenseRepository $offenses Offense history.
	 * @param EventRepository   $events   Event log.
	 */
	public function __construct(
		private BlockRepository $repo,
		private RuleCache $cache,
		private OffenseRepository $offenses,
		private EventRepository $events
	) {}

	/**
	 * Unblocks an IP.
	 *
	 * @param string $ip             IP text.
	 * @param bool   $include_ranges Also delete CIDR blocks containing the IP.
	 * @param int    $allow_hours    Add a temporary allowlist entry for this many hours (0 = none).
	 * @param int    $user_id        Acting user.
	 * @param string $method         "admin", "cli" or "email_link".
	 * @return array{removed:int, ranges:list<string>, allowed:bool}|null Null when the IP is invalid.
	 */
	public function unblock( string $ip, bool $include_ranges, int $allow_hours, int $user_id, string $method ): ?array {
		$cidr = Cidr::parse( $ip );
		if ( null === $cidr || ! $cidr->is_single() ) {
			return null;
		}
		$removed = 0;
		$ranges  = array();
		foreach ( $this->repo->find_containing( 'block', $cidr->start ) as $row ) {
			if ( $include_ranges || ( 4 === $cidr->version ? 32 : 128 ) === (int) $row['prefix'] ) {
				$removed += $this->repo->delete( (int) $row['id'] ) ? 1 : 0;
			} else {
				$ranges[] = (string) $row['label'];
			}
		}
		$allowed = false;
		if ( $allow_hours > 0 ) {
			$this->repo->add(
				'allow',
				$cidr,
				/* translators: %s: unlock method. */
				sprintf( __( 'Temporary allow after unlock (%s)', 'sentinel-shield' ), $method ),
				'unlock',
				time() + ( $allow_hours * HOUR_IN_SECONDS ),
				$user_id
			);
			$allowed = true;
		}
		$this->offenses->clear( $cidr->start );
		$this->cache->flush();
		$this->events->log(
			'unlock',
			array(
				'ip'      => $cidr->to_string(),
				'module'  => 'unlock',
				'reason'  => $method,
				'user_id' => $user_id,
				'context' => array(
					'removed'        => $removed,
					'ranges_kept'    => $ranges,
					'allowlisted_hr' => $allow_hours,
				),
			)
		);
		return array(
			'removed' => $removed,
			'ranges'  => $ranges,
			'allowed' => $allowed,
		);
	}
}
