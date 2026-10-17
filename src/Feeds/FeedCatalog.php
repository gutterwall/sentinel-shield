<?php
/**
 * Built-in public blocklist feeds.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Feeds;

use SentinelShield\Settings;

defined( 'ABSPATH' ) || exit;

/**
 * Each feed is opt-in. Terms notes only state what the provider publishes; when
 * a provider does not state reuse terms clearly the admin is told to check them.
 */
final class FeedCatalog {

	/**
	 * Terms categories shown as badges.
	 */
	public const TERMS_FREE           = 'free';
	public const TERMS_NONCOMMERCIAL  = 'noncommercial';
	public const TERMS_CHECK          = 'check';
	public const ALLOWED_UPDATE_HOURS = array( 12, 24, 48, 168 );

	/**
	 * Feed names keyed by slug. Untranslated proper nouns, safe to use before `init`.
	 */
	public const NAMES = array(
		'spamhaus_drop'  => 'Spamhaus DROP',
		'firehol_level1' => 'FireHOL Level 1',
		'et_compromised' => 'Emerging Threats: compromised hosts',
		'blocklist_de'   => 'blocklist.de (all)',
		'cins_army'      => 'CINS Army',
		'ipsum_3'        => 'IPsum (level 3)',
		'dshield_top'    => 'DShield top 20 attacking networks',
		'tor_exits'      => 'Tor exit nodes',
	);

	/**
	 * Feed definitions keyed by slug.
	 *
	 * Keys: name, urls, format (lines|spamhaus_json|dshield), min_entries (sanity floor:
	 * a smaller download is treated as broken and the previous copy is kept),
	 * min_hours (never fetched more often than this), terms, terms_url, about.
	 *
	 * @return array<string, array<string, mixed>>
	 */
	public static function all(): array {
		return array(
			'spamhaus_drop'  => array(
				'name'        => self::NAMES['spamhaus_drop'],
				'urls'        => array( 'https://www.spamhaus.org/drop/drop_v4.json', 'https://www.spamhaus.org/drop/drop_v6.json' ),
				'format'      => 'spamhaus_json',
				'min_entries' => 300,
				'min_hours'   => 12,
				'terms'       => self::TERMS_FREE,
				'terms_url'   => 'https://www.spamhaus.org/drop/terms/',
				'about'       => __( 'Hijacked and criminal-operated networks (IPv4 and IPv6). Very low false-positive rate. Free under the provider\'s terms, which forbid using the Spamhaus name in marketing.', 'sentinel-shield' ),
			),
			'firehol_level1' => array(
				'name'        => self::NAMES['firehol_level1'],
				'urls'        => array( 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset' ),
				'format'      => 'lines',
				'min_entries' => 1000,
				'min_hours'   => 12,
				'terms'       => self::TERMS_NONCOMMERCIAL,
				'terms_url'   => 'https://iplists.firehol.org/?ipset=firehol_level1',
				'about'       => __( 'Aggregate of Spamhaus DROP, DShield, Feodo and bogon lists, aimed at minimal false positives. Includes DShield data (CC BY-NC-SA), so treat it as non-commercial. Private and reserved ranges in it are skipped automatically.', 'sentinel-shield' ),
			),
			'et_compromised' => array(
				'name'        => self::NAMES['et_compromised'],
				'urls'        => array( 'https://rules.emergingthreats.net/blockrules/compromised-ips.txt' ),
				'format'      => 'lines',
				'min_entries' => 50,
				'min_hours'   => 12,
				'terms'       => self::TERMS_CHECK,
				'terms_url'   => 'https://rules.emergingthreats.net/blockrules/',
				'about'       => __( 'Hosts known to be compromised, published by Proofpoint Emerging Threats. Small list.', 'sentinel-shield' ),
			),
			'blocklist_de'   => array(
				'name'        => self::NAMES['blocklist_de'],
				'urls'        => array( 'https://lists.blocklist.de/lists/all.txt' ),
				'format'      => 'lines',
				'min_entries' => 1000,
				'min_hours'   => 12,
				'terms'       => self::TERMS_CHECK,
				'terms_url'   => 'https://www.blocklist.de/en/export.html',
				'about'       => __( 'IPs reported for SSH, mail, web and login attacks in the last 48 hours by fail2ban users. Large (20,000+ IPs) and fast-changing; dynamic IPs make occasional false positives more likely.', 'sentinel-shield' ),
			),
			'cins_army'      => array(
				'name'        => self::NAMES['cins_army'],
				'urls'        => array( 'https://cinsscore.com/list/ci-badguys.txt' ),
				'format'      => 'lines',
				'min_entries' => 1000,
				'min_hours'   => 12,
				'terms'       => self::TERMS_CHECK,
				'terms_url'   => 'https://cinsscore.com/',
				'about'       => __( 'IPs with poor reputation seen by the Sentinel IPS network. About 15,000 IPs.', 'sentinel-shield' ),
			),
			'ipsum_3'        => array(
				'name'        => self::NAMES['ipsum_3'],
				'urls'        => array( 'https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt' ),
				'format'      => 'lines',
				'min_entries' => 1000,
				'min_hours'   => 24,
				'terms'       => self::TERMS_FREE,
				'terms_url'   => 'https://github.com/stamparm/ipsum',
				'about'       => __( 'IPs that appear on at least 3 of 30+ public blocklists, rebuilt daily. Public domain (The Unlicense). Large (15,000+ IPs).', 'sentinel-shield' ),
			),
			'dshield_top'    => array(
				'name'        => self::NAMES['dshield_top'],
				'urls'        => array( 'https://feeds.dshield.org/block.txt' ),
				'format'      => 'dshield',
				'min_entries' => 5,
				'min_hours'   => 12,
				'terms'       => self::TERMS_NONCOMMERCIAL,
				'terms_url'   => 'https://feeds.dshield.org/block.txt',
				'about'       => __( 'The 20 /24 networks with the most attack reports over the last three days, from SANS ISC. Licensed CC BY-NC-SA: non-commercial use only.', 'sentinel-shield' ),
			),
			'tor_exits'      => array(
				'name'        => self::NAMES['tor_exits'],
				'urls'        => array( 'https://check.torproject.org/torbulkexitlist' ),
				'format'      => 'lines',
				'min_entries' => 100,
				'min_hours'   => 12,
				'terms'       => self::TERMS_FREE,
				'terms_url'   => 'https://check.torproject.org/',
				'about'       => __( 'Not a list of attackers: blocks everyone using the Tor anonymity network, including legitimate privacy-conscious visitors. Enable only if your site has no Tor audience.', 'sentinel-shield' ),
			),
		);
	}

	/**
	 * One feed, or null.
	 *
	 * @param string $slug Feed slug.
	 * @return array<string, mixed>|null
	 */
	public static function get( string $slug ): ?array {
		return self::all()[ $slug ] ?? null;
	}

	/**
	 * Slugs switched on in settings, in catalog order. Safe to call before `init`.
	 *
	 * @param Settings $settings Settings.
	 * @return list<string>
	 */
	public static function enabled_slugs( Settings $settings ): array {
		$out = array();
		foreach ( array_keys( self::NAMES ) as $slug ) {
			if ( $settings->get( "feeds.lists.$slug", false ) ) {
				$out[] = $slug;
			}
		}
		return $out;
	}

	/**
	 * Human label for a terms category.
	 *
	 * @param string $terms Terms category.
	 */
	public static function terms_label( string $terms ): string {
		return match ( $terms ) {
			self::TERMS_FREE          => __( 'Free to use', 'sentinel-shield' ),
			self::TERMS_NONCOMMERCIAL => __( 'Non-commercial only', 'sentinel-shield' ),
			default                   => __( 'Check provider terms', 'sentinel-shield' ),
		};
	}
}
