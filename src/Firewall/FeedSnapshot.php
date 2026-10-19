<?php
/**
 * Compiled blocklist feeds as a binary file.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Firewall;

use SentinelShield\Geo\GeoUpdater;
use SentinelShield\Net\IpRangeSet;
use SentinelShield\Net\RangeLookup;

defined( 'ABSPATH' ) || exit;

/**
 * Large blocklists (tens of thousands of ranges) would otherwise be read from
 * the cache and decoded on every request. The snapshot is a file of sorted,
 * merged ranges (a 16-byte header, then 8-byte IPv4 and 32-byte IPv6 records)
 * that a lookup binary-searches with a few small reads, so a request costs the
 * same whatever the list size. Files are written to a temporary name and
 * renamed into place, so readers never see a half-written snapshot.
 */
final class FeedSnapshot implements RangeLookup {

	public const MAGIC   = "SSFEED1\0";
	private const HEADER = 16;
	private const WIDTH  = array(
		4 => 8,
		6 => 32,
	);

	/**
	 * Open handles per path, for this request.
	 *
	 * @var array<string, resource>
	 */
	private static array $handles = array();

	/**
	 * Record counts: [v4, v6], read from the header.
	 *
	 * @var array{0:int, 1:int}|null
	 */
	private ?array $counts = null;

	/**
	 * Constructor.
	 *
	 * @param string $path Snapshot file.
	 */
	public function __construct( private string $path ) {}

	/**
	 * Snapshot file for a set of enabled feeds.
	 *
	 * @param list<string> $slugs Sorted feed slugs.
	 */
	public static function path( array $slugs ): string {
		return GeoUpdater::dir() . '/feeds-' . substr( md5( implode( ',', $slugs ) ), 0, 12 ) . '.bin';
	}

	/**
	 * Reads a whole range file back into a set (null if missing or damaged).
	 *
	 * @param string $path File.
	 */
	public static function read_set( string $path ): ?IpRangeSet {
		$raw = is_readable( $path ) ? (string) file_get_contents( $path ) : ''; // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Our own binary file.
		if ( strlen( $raw ) < self::HEADER || self::MAGIC !== substr( $raw, 0, 8 ) ) {
			return null;
		}
		$n = (array) unpack( 'Nv4/Nv6', substr( $raw, 8, 8 ) );
		if ( strlen( $raw ) !== self::HEADER + 8 * (int) $n['v4'] + 32 * (int) $n['v6'] ) {
			return null;
		}
		$pairs  = array();
		$offset = self::HEADER;
		foreach ( array(
			4  => (int) $n['v4'],
			16 => (int) $n['v6'],
		) as $len => $count ) {
			for ( $i = 0; $i < $count; $i++ ) {
				$pairs[] = array( substr( $raw, $offset, $len ), substr( $raw, $offset + $len, $len ) );
				$offset += 2 * $len;
			}
		}
		return IpRangeSet::from_pairs( $pairs );
	}

	/**
	 * Writes a snapshot. Returns false when the folder is not writable.
	 *
	 * @param IpRangeSet $set  Ranges.
	 * @param string     $path Destination.
	 */
	public static function write( IpRangeSet $set, string $path ): bool {
		$dir = dirname( $path );
		if ( ! is_dir( $dir ) && ! wp_mkdir_p( $dir ) ) {
			return false;
		}
		GeoUpdater::protect_dir( $dir );
		$v4  = $set->pairs( 4 );
		$v6  = $set->pairs( 6 );
		$tmp = $path . '.' . bin2hex( random_bytes( 4 ) ) . '.tmp';
		$out = @fopen( $tmp, 'wb' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- Unwritable folder: caller falls back.
		if ( false === $out ) {
			return false;
		}
		fwrite( $out, self::MAGIC . pack( 'NN', count( $v4 ), count( $v6 ) ) ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite -- Binary snapshot.
		foreach ( array( $v4, $v6 ) as $pairs ) {
			$buffer = '';
			foreach ( $pairs as $pair ) {
				$buffer .= $pair[0] . $pair[1];
				if ( strlen( $buffer ) > 65536 ) {
					fwrite( $out, $buffer ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite -- Binary snapshot.
					$buffer = '';
				}
			}
			fwrite( $out, $buffer ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite -- Binary snapshot.
		}
		fclose( $out ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- Binary snapshot.
		self::close( $path );
		if ( ! @rename( $tmp, $path ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.rename_rename -- Atomic replace.
			wp_delete_file( $tmp );
			return false;
		}
		return true;
	}

	/**
	 * Deletes every snapshot (after a feed update or a change of enabled feeds).
	 */
	public static function delete_all(): void {
		foreach ( (array) glob( GeoUpdater::dir() . '/feeds-*.bin' ) as $file ) {
			self::close( (string) $file );
			wp_delete_file( (string) $file );
		}
	}

	/**
	 * Whether the snapshot file exists and is well formed.
	 */
	public function valid(): bool {
		return null !== $this->counts();
	}

	/**
	 * Whether a packed IP is in a listed range.
	 *
	 * @param string $bin Packed IP.
	 */
	public function contains( string $bin ): bool {
		$len = strlen( $bin );
		if ( 4 !== $len && 16 !== $len ) {
			return false;
		}
		$counts = $this->counts();
		$h      = self::$handles[ $this->path ] ?? null;
		if ( null === $counts || null === $h ) {
			return false;
		}
		$version = 4 === $len ? 4 : 6;
		$width   = self::WIDTH[ $version ];
		$base    = self::HEADER + ( 6 === $version ? $counts[0] * self::WIDTH[4] : 0 );
		$lo      = 0;
		$hi      = ( 4 === $version ? $counts[0] : $counts[1] ) - 1;
		while ( $lo <= $hi ) {
			$mid = ( $lo + $hi ) >> 1;
			fseek( $h, $base + $mid * $width );
			$row = (string) fread( $h, $width ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fread -- Binary snapshot.
			if ( strlen( $row ) !== $width ) {
				return false;
			}
			if ( strcmp( $bin, substr( $row, 0, $len ) ) < 0 ) {
				$hi = $mid - 1;
			} elseif ( strcmp( $bin, substr( $row, $len, $len ) ) > 0 ) {
				$lo = $mid + 1;
			} else {
				return true;
			}
		}
		return false;
	}

	/**
	 * Number of ranges.
	 */
	public function count(): int {
		$counts = $this->counts();
		return null === $counts ? 0 : $counts[0] + $counts[1];
	}

	/**
	 * Header counts, opening the file once per request.
	 *
	 * @return array{0:int, 1:int}|null
	 */
	private function counts(): ?array {
		if ( null !== $this->counts ) {
			return $this->counts;
		}
		if ( ! isset( self::$handles[ $this->path ] ) ) {
			$h = is_file( $this->path ) ? @fopen( $this->path, 'rb' ) : false; // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- Missing file: no snapshot.
			if ( false === $h ) {
				return null;
			}
			self::$handles[ $this->path ] = $h;
		}
		$h = self::$handles[ $this->path ];
		fseek( $h, 0 );
		$head = (string) fread( $h, self::HEADER ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fread -- Binary snapshot.
		if ( strlen( $head ) !== self::HEADER || ! str_starts_with( $head, self::MAGIC ) ) {
			return null;
		}
		$n    = (array) unpack( 'Nv4/Nv6', substr( $head, 8 ) );
		$size = self::HEADER + (int) $n['v4'] * self::WIDTH[4] + (int) $n['v6'] * self::WIDTH[6];
		$stat = fstat( $h );
		if ( ! is_array( $stat ) || (int) $stat['size'] !== $size ) {
			return null;
		}
		$this->counts = array( (int) $n['v4'], (int) $n['v6'] );
		return $this->counts;
	}

	/**
	 * Closes a cached handle (before replacing or deleting the file).
	 *
	 * @param string $path File.
	 */
	public static function close( string $path ): void {
		if ( isset( self::$handles[ $path ] ) ) {
			fclose( self::$handles[ $path ] ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- Binary snapshot.
			unset( self::$handles[ $path ] );
		}
	}
}
