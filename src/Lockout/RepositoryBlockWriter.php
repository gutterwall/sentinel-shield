<?php
/**
 * BlockWriter backed by the rules table.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Lockout;

use SentinelShield\Firewall\RuleCache;
use SentinelShield\Net\Cidr;
use SentinelShield\Repository\BlockRepository;

defined( 'ABSPATH' ) || exit;

/**
 * Persists lockout blocks and invalidates the rule cache.
 */
final class RepositoryBlockWriter implements BlockWriter {

	/**
	 * Constructor.
	 *
	 * @param BlockRepository $repo  Rules.
	 * @param RuleCache       $cache Cache.
	 */
	public function __construct( private BlockRepository $repo, private RuleCache $cache ) {}

	/**
	 * {@inheritDoc}
	 *
	 * @param string   $ip      IP text.
	 * @param int|null $expires Unix expiry, null = permanent.
	 * @param string   $reason  Reason.
	 * @param string   $source  Source.
	 */
	public function block( string $ip, ?int $expires, string $reason, string $source ): bool {
		$cidr = Cidr::parse( $ip );
		if ( null === $cidr ) {
			return false;
		}
		$this->repo->add( 'block', $cidr, $reason, $source, $expires );
		$this->cache->flush();
		return true;
	}
}
