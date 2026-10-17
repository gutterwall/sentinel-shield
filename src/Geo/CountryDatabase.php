<?php
/**
 * Local IP-to-country database: a sorted binary range file built from a CSV.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Geo;

defined( 'ABSPATH' ) || exit;

// phpcs:disable WordPress.WP.AlternativeFunctions -- Binary random-access file I/O; WP_Filesystem cannot seek.

/**
 * File layout: 20-byte header (8-byte magic, IPv4 count, IPv6 count, build time,
 * all big-endian uint32), then fixed-width records sorted by start address:
 * IPv4 as start(4) end(4) country(2), IPv6 as start(16) end(16) country(2).
 * Adjacent ranges with the same country are merged. A lookup is a binary search
 * with about 20 seeks, so nothing is loaded into memory.
 *
 * The CSV format is "start IP,end IP,country code" per line, gzip or plain,
 * sorted by start address: DB-IP's "IP to Country Lite" format.
 */
final class CountryDatabase {

	private const MAGIC  = "SSGEO1\0\0";
	private const HEADER = 20;

	/**
	 * Open file handles by path, kept for the request.
	 *
	 * @var array<string, resource>
	 */
	private static array $handles = array();

	/**
	 * Constructor.
	 *
	 * @param string $path Database file.
	 */
	public function __construct( private string $path ) {}

	/**
	 * The database file path.
	 */
	public function path(): string {
		return $this->path;
	}

	/**
	 * Header details, or null when the file is missing or invalid.
	 *
	 * @return array{v4:int, v6:int, built:int, size:int}|null
	 */
	public function info(): ?array {
		$h = $this->handle();
		if ( null === $h ) {
			return null;
		}
		fseek( $h, 0 );
		$head = (string) fread( $h, self::HEADER );
		if ( strlen( $head ) !== self::HEADER || 0 !== strncmp( $head, self::MAGIC, 8 ) ) {
			return null;
		}
		$n    = (array) unpack( 'Nv4/Nv6/Nbuilt', substr( $head, 8 ) );
		$size = (int) filesize( $this->path );
		if ( self::HEADER + (int) $n['v4'] * 10 + (int) $n['v6'] * 34 !== $size ) {
			return null;
		}
		return array(
			'v4'    => (int) $n['v4'],
			'v6'    => (int) $n['v6'],
			'built' => (int) $n['built'],
			'size'  => $size,
		);
	}

	/**
	 * Country code for a packed address, or '' when not listed.
	 *
	 * @param string $bin Packed IPv4 (4 bytes) or IPv6 (16 bytes) address.
	 */
	public function lookup( string $bin ): string {
		$width = strlen( $bin );
		$info  = 4 === $width || 16 === $width ? $this->info() : null;
		if ( null === $info ) {
			return '';
		}
		$h      = self::$handles[ $this->path ];
		$record = 2 * $width + 2;
		$count  = 4 === $width ? $info['v4'] : $info['v6'];
		$base   = self::HEADER + ( 4 === $width ? 0 : $info['v4'] * 10 );
		$lo     = 0;
		$hi     = $count - 1;
		$found  = '';
		// Last record whose start is <= the address.
		while ( $lo <= $hi ) {
			$mid = intdiv( $lo + $hi, 2 );
			fseek( $h, $base + $mid * $record );
			$row = (string) fread( $h, $record );
			if ( strcmp( substr( $row, 0, $width ), $bin ) <= 0 ) {
				$found = $row;
				$lo    = $mid + 1;
			} else {
				$hi = $mid - 1;
			}
		}
		if ( '' === $found || strcmp( $bin, substr( $found, $width, $width ) ) > 0 ) {
			return '';
		}
		return substr( $found, 2 * $width, 2 );
	}

	/**
	 * Builds a database file from a CSV (gzip or plain). The new file replaces
	 * the old one only once it is complete.
	 *
	 * @param string $csv  Source file.
	 * @param string $dest Database file to write.
	 * @return array{v4:int, v6:int, rows:int}
	 * @throws \RuntimeException When the input is unreadable, unsorted or overlapping.
	 */
	public static function build( string $csv, string $dest ): array {
		$in = gzopen( $csv, 'rb' );
		if ( false === $in ) {
			throw new \RuntimeException( 'Cannot read ' . basename( $csv ) ); // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- Caught by GeoUpdater and shown escaped.
		}
		$parts = array(
			4  => fopen( 'php://temp/maxmemory:8388608', 'w+b' ),
			16 => fopen( 'php://temp/maxmemory:8388608', 'w+b' ),
		);
		$count = array(
			4  => 0,
			16 => 0,
		);
		$prev  = array(
			4  => null,
			16 => null,
		);
		$rows  = 0;
		$line  = 0;
		try {
			while ( ! gzeof( $in ) ) {
				$text = gzgets( $in, 512 );
				++$line;
				if ( false === $text ) {
					break;
				}
				$cols = array_map( static fn( string $c ): string => trim( $c, " \t\r\n\"" ), explode( ',', $text ) );
				if ( count( $cols ) < 3 ) {
					continue;
				}
				$start = inet_pton( $cols[0] );
				$end   = inet_pton( $cols[1] );
				if ( false === $start || false === $end ) {
					// Header or comment line.
					continue;
				}
				$width = strlen( $start );
				$cc    = strtoupper( $cols[2] );
				if ( strlen( $end ) !== $width || strcmp( $start, $end ) > 0 ) {
					throw new \RuntimeException( sprintf( 'Invalid range on line %d', $line ) );
				}
				$last = $prev[ $width ];
				if ( null !== $last && strcmp( $start, $last[1] ) <= 0 ) {
					throw new \RuntimeException( sprintf( 'Ranges are not sorted or overlap on line %d', $line ) );
				}
				++$rows;
				if ( ! preg_match( '/^[A-Z][A-Z0-9]$/', $cc ) || 'ZZ' === $cc ) {
					// Unknown or reserved space: leave a gap. Flush the open range.
					if ( null !== $last && '' !== $last[2] ) {
						self::write( $parts[ $width ], $last );
						++$count[ $width ];
					}
					$prev[ $width ] = array( $start, $end, '' );
					continue;
				}
				if ( null !== $last && $last[2] === $cc && self::increment( $last[1] ) === $start ) {
					$prev[ $width ][1] = $end;
					continue;
				}
				if ( null !== $last && '' !== $last[2] ) {
					self::write( $parts[ $width ], $last );
					++$count[ $width ];
				}
				$prev[ $width ] = array( $start, $end, $cc );
			}
			foreach ( array( 4, 16 ) as $width ) {
				if ( null !== $prev[ $width ] && '' !== $prev[ $width ][2] ) {
					self::write( $parts[ $width ], $prev[ $width ] );
					++$count[ $width ];
				}
			}

			$tmp = $dest . '.tmp';
			$out = fopen( $tmp, 'wb' );
			if ( false === $out ) {
				throw new \RuntimeException( 'Cannot write ' . basename( $tmp ) );
			}
			fwrite( $out, self::MAGIC . pack( 'NNN', $count[4], $count[16], time() ) );
			foreach ( $parts as $part ) {
				rewind( $part );
				stream_copy_to_stream( $part, $out );
			}
			fclose( $out );
			self::close( $dest );
			if ( ! rename( $tmp, $dest ) ) {
				wp_delete_file( $tmp );
				throw new \RuntimeException( 'Cannot replace ' . basename( $dest ) );
			}
		} finally {
			gzclose( $in );
			foreach ( $parts as $part ) {
				fclose( $part );
			}
		}
		return array(
			'v4'   => $count[4],
			'v6'   => $count[16],
			'rows' => $rows,
		);
	}

	/**
	 * Deletes the database file.
	 */
	public function delete(): void {
		self::close( $this->path );
		if ( is_file( $this->path ) ) {
			wp_delete_file( $this->path );
		}
	}

	/**
	 * Closes a cached handle (before the file is replaced or deleted).
	 *
	 * @param string $path File.
	 */
	public static function close( string $path ): void {
		if ( isset( self::$handles[ $path ] ) ) {
			fclose( self::$handles[ $path ] );
			unset( self::$handles[ $path ] );
		}
	}

	/**
	 * The file handle, opened once per request.
	 *
	 * @return resource|null
	 */
	private function handle() {
		if ( ! isset( self::$handles[ $this->path ] ) ) {
			if ( ! is_file( $this->path ) || ! is_readable( $this->path ) ) {
				return null;
			}
			$h = fopen( $this->path, 'rb' );
			if ( false === $h ) {
				return null;
			}
			self::$handles[ $this->path ] = $h;
		}
		return self::$handles[ $this->path ];
	}

	/**
	 * Writes one record.
	 *
	 * @param resource                            $out    Stream.
	 * @param array{0:string, 1:string, 2:string} $range Start, end, country.
	 */
	private static function write( $out, array $range ): void {
		fwrite( $out, $range[0] . $range[1] . $range[2] );
	}

	/**
	 * Adds one to a packed address (wrapping to all zeros after the maximum).
	 *
	 * @param string $bin Packed address.
	 */
	private static function increment( string $bin ): string {
		for ( $i = strlen( $bin ) - 1; $i >= 0; $i-- ) {
			$byte = ord( $bin[ $i ] );
			if ( $byte < 255 ) {
				$bin[ $i ] = chr( $byte + 1 );
				return $bin;
			}
			$bin[ $i ] = "\0";
		}
		return $bin;
	}
}
