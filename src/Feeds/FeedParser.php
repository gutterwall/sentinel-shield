<?php
/**
 * Turns downloaded blocklist bodies into safe, de-duplicated ranges.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Feeds;

use SentinelShield\Net\Cidr;

defined( 'ABSPATH' ) || exit;

/**
 * Pure parsing, no WordPress calls. Entries that could hurt the site are dropped:
 * private, loopback, link-local, multicast and other reserved space (FireHOL
 * level 1 ships 10.0.0.0/8 and 127.0.0.0/8 as "bogons"), and implausibly broad
 * ranges (shorter than /8 for IPv4 or /16 for IPv6).
 */
final class FeedParser {

	public const MAX_ENTRIES  = 200000;
	public const MIN_PREFIX_4 = 8;
	public const MIN_PREFIX_6 = 16;

	/**
	 * Special-purpose ranges that must never come from a feed. IPv4-mapped IPv6
	 * (::ffff:0:0/96) is absent on purpose: Cidr normalizes it to IPv4, where the
	 * IPv4 entries apply.
	 */
	public const RESERVED = array(
		'0.0.0.0/8',
		'10.0.0.0/8',
		'100.64.0.0/10',
		'127.0.0.0/8',
		'169.254.0.0/16',
		'172.16.0.0/12',
		'192.0.0.0/24',
		'192.0.2.0/24',
		'192.168.0.0/16',
		'198.18.0.0/15',
		'198.51.100.0/24',
		'203.0.113.0/24',
		'224.0.0.0/3',
		'::/127',
		'64:ff9b::/96',
		'100::/64',
		'2001:db8::/32',
		'fc00::/7',
		'fe80::/10',
		'ff00::/8',
	);

	/**
	 * Parsed reserved ranges.
	 *
	 * @var list<Cidr>|null
	 */
	private static ?array $reserved = null;

	/**
	 * Parses one downloaded body.
	 *
	 * @param string $format lines|spamhaus_json|dshield.
	 * @param string $body   Raw body.
	 * @return array{ranges: list<Cidr>, skipped: int}
	 */
	public static function parse( string $format, string $body ): array {
		$ranges  = array();
		$skipped = 0;
		$lines   = preg_split( '/\r\n|\r|\n/', $body );
		foreach ( false === $lines ? array() : $lines as $line ) {
			$value = match ( $format ) {
				'spamhaus_json' => self::spamhaus_entry( $line ),
				'dshield'       => self::dshield_entry( $line ),
				default         => self::plain_entry( $line ),
			};
			if ( null === $value ) {
				continue;
			}
			$cidr = Cidr::parse( $value );
			if ( null === $cidr || ! self::is_acceptable( $cidr ) ) {
				++$skipped;
				continue;
			}
			$ranges[ $cidr->start . $cidr->end ] = $cidr;
			if ( count( $ranges ) >= self::MAX_ENTRIES ) {
				break;
			}
		}
		return array(
			'ranges'  => array_values( $ranges ),
			'skipped' => $skipped,
		);
	}

	/**
	 * First token of a plain list line; '#' and ';' start comments. Null for blank/comment lines.
	 *
	 * @param string $line Line.
	 */
	public static function plain_entry( string $line ): ?string {
		$line = trim( (string) preg_replace( '/[#;].*$/', '', $line ) );
		if ( '' === $line ) {
			return null;
		}
		return (string) preg_split( '/[\s,]+/', $line )[0];
	}

	/**
	 * CIDR from a Spamhaus JSON line; the metadata line has no "cidr" key.
	 *
	 * @param string $line Line.
	 */
	private static function spamhaus_entry( string $line ): ?string {
		$line = trim( $line );
		if ( '' === $line || '{' !== $line[0] ) {
			return null;
		}
		$row = json_decode( $line, true );
		return is_array( $row ) && isset( $row['cidr'] ) && is_string( $row['cidr'] ) ? $row['cidr'] : null;
	}

	/**
	 * "start<TAB>end<TAB>prefix..." rows from DShield block.txt.
	 *
	 * @param string $line Line.
	 */
	private static function dshield_entry( string $line ): ?string {
		$line = trim( $line );
		if ( '' === $line || '#' === $line[0] || str_starts_with( $line, 'Start' ) ) {
			return null;
		}
		$cols = preg_split( '/\s+/', $line );
		if ( false === $cols || count( $cols ) < 3 || ! ctype_digit( $cols[2] ) ) {
			return null;
		}
		return $cols[0] . '/' . $cols[2];
	}

	/**
	 * Whether a range is specific enough and outside reserved space.
	 *
	 * @param Cidr $cidr Range.
	 */
	public static function is_acceptable( Cidr $cidr ): bool {
		if ( $cidr->prefix < ( 4 === $cidr->version ? self::MIN_PREFIX_4 : self::MIN_PREFIX_6 ) ) {
			return false;
		}
		foreach ( self::reserved() as $reserved ) {
			if ( $reserved->version === $cidr->version
				&& strcmp( $cidr->start, $reserved->end ) <= 0
				&& strcmp( $cidr->end, $reserved->start ) >= 0 ) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Parsed RESERVED list.
	 *
	 * @return list<Cidr>
	 */
	private static function reserved(): array {
		if ( null === self::$reserved ) {
			self::$reserved = array();
			foreach ( self::RESERVED as $range ) {
				$cidr = Cidr::parse( $range );
				if ( null !== $cidr ) {
					self::$reserved[] = $cidr;
				}
			}
		}
		return self::$reserved;
	}
}
