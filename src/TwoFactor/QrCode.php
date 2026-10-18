<?php
/**
 * Minimal QR code generator (byte mode, error correction level M) with SVG output.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\TwoFactor;

defined( 'ABSPATH' ) || exit;

/**
 * Draws the authenticator setup QR code on the server, so the TOTP secret is
 * never sent to a third-party QR service or loaded into a JavaScript library.
 * Implements ISO/IEC 18004 for versions 1-20 (up to 666 bytes), level M,
 * with the standard mask selection.
 */
final class QrCode {

	/**
	 * Level M blocks per version: EC codewords per block, then [count, data
	 * codewords] for each block group.
	 */
	private const BLOCKS = array(
		1  => array( 10, array( array( 1, 16 ) ) ),
		2  => array( 16, array( array( 1, 28 ) ) ),
		3  => array( 26, array( array( 1, 44 ) ) ),
		4  => array( 18, array( array( 2, 32 ) ) ),
		5  => array( 24, array( array( 2, 43 ) ) ),
		6  => array( 16, array( array( 4, 27 ) ) ),
		7  => array( 18, array( array( 4, 31 ) ) ),
		8  => array( 22, array( array( 2, 38 ), array( 2, 39 ) ) ),
		9  => array( 22, array( array( 3, 36 ), array( 2, 37 ) ) ),
		10 => array( 26, array( array( 4, 43 ), array( 1, 44 ) ) ),
		11 => array( 30, array( array( 1, 50 ), array( 4, 51 ) ) ),
		12 => array( 22, array( array( 6, 36 ), array( 2, 37 ) ) ),
		13 => array( 22, array( array( 8, 37 ), array( 1, 38 ) ) ),
		14 => array( 24, array( array( 4, 40 ), array( 5, 41 ) ) ),
		15 => array( 24, array( array( 5, 41 ), array( 5, 42 ) ) ),
		16 => array( 28, array( array( 7, 45 ), array( 3, 46 ) ) ),
		17 => array( 28, array( array( 10, 46 ), array( 1, 47 ) ) ),
		18 => array( 26, array( array( 9, 43 ), array( 4, 44 ) ) ),
		19 => array( 26, array( array( 3, 44 ), array( 11, 45 ) ) ),
		20 => array( 26, array( array( 3, 41 ), array( 13, 42 ) ) ),
	);

	/**
	 * Alignment pattern centres per version.
	 */
	private const ALIGN = array(
		1  => array(),
		2  => array( 6, 18 ),
		3  => array( 6, 22 ),
		4  => array( 6, 26 ),
		5  => array( 6, 30 ),
		6  => array( 6, 34 ),
		7  => array( 6, 22, 38 ),
		8  => array( 6, 24, 42 ),
		9  => array( 6, 26, 46 ),
		10 => array( 6, 28, 50 ),
		11 => array( 6, 30, 54 ),
		12 => array( 6, 32, 58 ),
		13 => array( 6, 34, 62 ),
		14 => array( 6, 26, 46, 66 ),
		15 => array( 6, 26, 48, 70 ),
		16 => array( 6, 26, 50, 74 ),
		17 => array( 6, 30, 54, 78 ),
		18 => array( 6, 30, 56, 82 ),
		19 => array( 6, 30, 58, 86 ),
		20 => array( 6, 34, 62, 90 ),
	);

	/**
	 * Module colours, [y][x], true = dark.
	 *
	 * @var list<list<bool>>
	 */
	private array $modules = array();

	/**
	 * Function pattern (not data) flags, [y][x].
	 *
	 * @var list<list<bool>>
	 */
	private array $reserved = array();

	/**
	 * Side length in modules.
	 *
	 * @var int
	 */
	private int $size = 0;

	/**
	 * Encodes text and returns the module matrix, [y][x], true = dark.
	 *
	 * @param string $text Bytes to encode.
	 * @return list<list<bool>>
	 * @throws \LengthException When the text does not fit in version 20.
	 */
	public static function matrix( string $text ): array {
		$qr = new self();
		return $qr->encode( $text );
	}

	/**
	 * Encodes text as an SVG image.
	 *
	 * @param string $text  Bytes to encode.
	 * @param int    $scale Pixels per module.
	 * @param string $label Accessible name.
	 */
	public static function svg( string $text, int $scale = 4, string $label = '' ): string {
		$matrix = self::matrix( $text );
		$size   = count( $matrix );
		$quiet  = 4;
		$full   = $size + 2 * $quiet;
		$path   = '';
		foreach ( $matrix as $y => $row ) {
			foreach ( $row as $x => $dark ) {
				if ( $dark ) {
					$path .= 'M' . ( $x + $quiet ) . ' ' . ( $y + $quiet ) . 'h1v1h-1z';
				}
			}
		}
		$px = $full * $scale;
		return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' . $full . ' ' . $full . '" width="' . $px . '" height="' . $px . '" shape-rendering="crispEdges" role="img" aria-label="' . htmlspecialchars( $label, ENT_QUOTES ) . '">'
			. '<rect width="100%" height="100%" fill="#fff"/><path fill="#000" d="' . $path . '"/></svg>';
	}

	/**
	 * Builds the symbol.
	 *
	 * @param string $text Bytes.
	 * @return list<list<bool>>
	 * @throws \LengthException When the text is too long.
	 */
	private function encode( string $text ): array {
		$length  = strlen( $text );
		$version = 0;
		foreach ( self::BLOCKS as $v => $spec ) {
			$capacity = self::data_codewords( $v ) * 8;
			$needed   = 4 + ( $v < 10 ? 8 : 16 ) + 8 * $length;
			if ( $needed <= $capacity ) {
				$version = $v;
				break;
			}
		}
		if ( 0 === $version ) {
			throw new \LengthException( 'Text too long for a QR code' );
		}

		// Data bits: byte mode indicator, length, bytes, terminator, padding.
		$bits = '0100' . str_pad( decbin( $length ), $version < 10 ? 8 : 16, '0', STR_PAD_LEFT );
		for ( $i = 0; $i < $length; $i++ ) {
			$bits .= str_pad( decbin( ord( $text[ $i ] ) ), 8, '0', STR_PAD_LEFT );
		}
		$capacity = self::data_codewords( $version ) * 8;
		$bits    .= str_repeat( '0', min( 4, $capacity - strlen( $bits ) ) );
		$bits    .= str_repeat( '0', ( 8 - strlen( $bits ) % 8 ) % 8 );
		$data     = array_map( 'bindec', str_split( $bits, 8 ) );
		for ( $pad = 0; count( $data ) < $capacity / 8; $pad ^= 1 ) {
			$data[] = $pad ? 0x11 : 0xEC;
		}

		$codewords = $this->add_error_correction( $data, $version );

		$this->size     = 17 + 4 * $version;
		$this->modules  = array_fill( 0, $this->size, array_fill( 0, $this->size, false ) );
		$this->reserved = $this->modules;
		$this->draw_function_patterns( $version );
		$this->draw_codewords( $codewords );

		// Pick the mask with the lowest penalty.
		$best  = 0;
		$score = PHP_INT_MAX;
		$plain = $this->modules;
		for ( $mask = 0; $mask < 8; $mask++ ) {
			$this->apply_mask( $mask );
			$this->draw_format( $mask );
			$penalty = $this->penalty();
			if ( $penalty < $score ) {
				$score = $penalty;
				$best  = $mask;
			}
			$this->modules = $plain;
		}
		$this->apply_mask( $best );
		$this->draw_format( $best );
		return $this->modules;
	}

	/**
	 * Total data codewords of a version.
	 *
	 * @param int $version Version.
	 */
	private static function data_codewords( int $version ): int {
		$total = 0;
		foreach ( self::BLOCKS[ $version ][1] as $group ) {
			$total += $group[0] * $group[1];
		}
		return $total;
	}

	/**
	 * Splits data into blocks, adds Reed-Solomon codewords and interleaves.
	 *
	 * @param list<int> $data    Data codewords.
	 * @param int       $version Version.
	 * @return list<int>
	 */
	private function add_error_correction( array $data, int $version ): array {
		[ $ec_len, $groups ] = self::BLOCKS[ $version ];
		$generator           = self::rs_generator( $ec_len );
		$blocks              = array();
		$offset              = 0;
		foreach ( $groups as $group ) {
			for ( $b = 0; $b < $group[0]; $b++ ) {
				$chunk    = array_slice( $data, $offset, $group[1] );
				$offset  += $group[1];
				$blocks[] = array( $chunk, self::rs_remainder( $chunk, $generator ) );
			}
		}
		$out     = array();
		$longest = max( array_map( static fn( array $b ): int => count( $b[0] ), $blocks ) );
		for ( $i = 0; $i < $longest; $i++ ) {
			foreach ( $blocks as $block ) {
				if ( isset( $block[0][ $i ] ) ) {
					$out[] = $block[0][ $i ];
				}
			}
		}
		for ( $i = 0; $i < $ec_len; $i++ ) {
			foreach ( $blocks as $block ) {
				$out[] = $block[1][ $i ];
			}
		}
		return $out;
	}

	/**
	 * Multiplies in GF(256) with the QR polynomial 0x11D.
	 *
	 * @param int $a Factor.
	 * @param int $b Factor.
	 */
	private static function gf_mul( int $a, int $b ): int {
		$result = 0;
		for ( $i = 7; $i >= 0; $i-- ) {
			$result = ( $result << 1 ) ^ ( ( $result >> 7 ) * 0x11D );
			$result ^= ( ( $b >> $i ) & 1 ) * $a;
		}
		return $result & 0xff;
	}

	/**
	 * Reed-Solomon generator polynomial coefficients (highest degree omitted).
	 *
	 * @param int $degree Number of EC codewords.
	 * @return list<int>
	 */
	private static function rs_generator( int $degree ): array {
		$result               = array_fill( 0, $degree, 0 );
		$result[ $degree - 1 ] = 1;
		$root                 = 1;
		for ( $i = 0; $i < $degree; $i++ ) {
			for ( $j = 0; $j < $degree; $j++ ) {
				$result[ $j ] = self::gf_mul( $result[ $j ], $root );
				if ( $j + 1 < $degree ) {
					$result[ $j ] ^= $result[ $j + 1 ];
				}
			}
			$root = self::gf_mul( $root, 0x02 );
		}
		return $result;
	}

	/**
	 * Reed-Solomon remainder (the EC codewords) of a data block.
	 *
	 * @param list<int> $data      Data codewords.
	 * @param list<int> $generator Generator.
	 * @return list<int>
	 */
	private static function rs_remainder( array $data, array $generator ): array {
		$degree = count( $generator );
		$result = array_fill( 0, $degree, 0 );
		foreach ( $data as $byte ) {
			$factor = $byte ^ array_shift( $result );
			$result[] = 0;
			for ( $i = 0; $i < $degree; $i++ ) {
				$result[ $i ] ^= self::gf_mul( $generator[ $i ], $factor );
			}
		}
		return $result;
	}

	/**
	 * Sets a function module.
	 *
	 * @param int  $x    Column.
	 * @param int  $y    Row.
	 * @param bool $dark Colour.
	 */
	private function set( int $x, int $y, bool $dark ): void {
		$this->modules[ $y ][ $x ]  = $dark;
		$this->reserved[ $y ][ $x ] = true;
	}

	/**
	 * Finder, timing and alignment patterns, and reserved format/version areas.
	 *
	 * @param int $version Version.
	 */
	private function draw_function_patterns( int $version ): void {
		$size = $this->size;
		for ( $i = 0; $i < $size; $i++ ) {
			$this->set( 6, $i, 0 === $i % 2 );
			$this->set( $i, 6, 0 === $i % 2 );
		}
		foreach ( array( array( 3, 3 ), array( $size - 4, 3 ), array( 3, $size - 4 ) ) as [ $cx, $cy ] ) {
			for ( $dy = -4; $dy <= 4; $dy++ ) {
				for ( $dx = -4; $dx <= 4; $dx++ ) {
					$x = $cx + $dx;
					$y = $cy + $dy;
					if ( $x >= 0 && $x < $size && $y >= 0 && $y < $size ) {
						$dist = max( abs( $dx ), abs( $dy ) );
						$this->set( $x, $y, 2 !== $dist && 4 !== $dist );
					}
				}
			}
		}
		$align = self::ALIGN[ $version ];
		$count = count( $align );
		foreach ( $align as $i => $cx ) {
			foreach ( $align as $j => $cy ) {
				// Skip the three corners that hold finder patterns.
				if ( ( 0 === $i && 0 === $j ) || ( 0 === $i && $count - 1 === $j ) || ( $count - 1 === $i && 0 === $j ) ) {
					continue;
				}
				for ( $dy = -2; $dy <= 2; $dy++ ) {
					for ( $dx = -2; $dx <= 2; $dx++ ) {
						$this->set( $cx + $dx, $cy + $dy, 1 !== max( abs( $dx ), abs( $dy ) ) );
					}
				}
			}
		}
		// Reserve the format areas now; they are drawn per mask.
		$this->draw_format( 0 );
		if ( $version >= 7 ) {
			$rem = $version;
			for ( $i = 0; $i < 12; $i++ ) {
				$rem = ( $rem << 1 ) ^ ( ( $rem >> 11 ) * 0x1F25 );
			}
			$bits = ( $version << 12 ) | $rem;
			for ( $i = 0; $i < 18; $i++ ) {
				$dark = 1 === ( ( $bits >> $i ) & 1 );
				$a    = $size - 11 + $i % 3;
				$b    = intdiv( $i, 3 );
				$this->set( $a, $b, $dark );
				$this->set( $b, $a, $dark );
			}
		}
	}

	/**
	 * Format information (level M and the mask) in both copies, plus the dark module.
	 *
	 * @param int $mask Mask number.
	 */
	private function draw_format( int $mask ): void {
		$data = ( 0 << 3 ) | $mask; // Level M = 00.
		$rem  = $data;
		for ( $i = 0; $i < 10; $i++ ) {
			$rem = ( $rem << 1 ) ^ ( ( $rem >> 9 ) * 0x537 );
		}
		$bits = ( ( $data << 10 ) | $rem ) ^ 0x5412;
		$bit  = static fn( int $i ): bool => 1 === ( ( $bits >> $i ) & 1 );
		$size = $this->size;
		for ( $i = 0; $i <= 5; $i++ ) {
			$this->set( 8, $i, $bit( $i ) );
		}
		$this->set( 8, 7, $bit( 6 ) );
		$this->set( 8, 8, $bit( 7 ) );
		$this->set( 7, 8, $bit( 8 ) );
		for ( $i = 9; $i < 15; $i++ ) {
			$this->set( 14 - $i, 8, $bit( $i ) );
		}
		for ( $i = 0; $i < 8; $i++ ) {
			$this->set( $size - 1 - $i, 8, $bit( $i ) );
		}
		for ( $i = 8; $i < 15; $i++ ) {
			$this->set( 8, $size - 15 + $i, $bit( $i ) );
		}
		$this->set( 8, $size - 8, true );
	}

	/**
	 * Places the codewords in the zigzag order.
	 *
	 * @param list<int> $codewords Interleaved codewords.
	 */
	private function draw_codewords( array $codewords ): void {
		$size  = $this->size;
		$total = count( $codewords ) * 8;
		$i     = 0;
		for ( $right = $size - 1; $right >= 1; $right -= 2 ) {
			if ( 6 === $right ) {
				$right = 5;
			}
			$upward = 0 === ( ( $right + 1 ) & 2 );
			for ( $vert = 0; $vert < $size; $vert++ ) {
				for ( $j = 0; $j < 2; $j++ ) {
					$x = $right - $j;
					$y = $upward ? $size - 1 - $vert : $vert;
					if ( ! $this->reserved[ $y ][ $x ] && $i < $total ) {
						$this->modules[ $y ][ $x ] = 1 === ( ( $codewords[ $i >> 3 ] >> ( 7 - ( $i & 7 ) ) ) & 1 );
						++$i;
					}
				}
			}
		}
	}

	/**
	 * XORs a mask pattern over the data modules.
	 *
	 * @param int $mask Mask number.
	 */
	private function apply_mask( int $mask ): void {
		for ( $y = 0; $y < $this->size; $y++ ) {
			for ( $x = 0; $x < $this->size; $x++ ) {
				if ( $this->reserved[ $y ][ $x ] ) {
					continue;
				}
				$flip = match ( $mask ) {
					0 => 0 === ( $x + $y ) % 2,
					1 => 0 === $y % 2,
					2 => 0 === $x % 3,
					3 => 0 === ( $x + $y ) % 3,
					4 => 0 === ( intdiv( $x, 3 ) + intdiv( $y, 2 ) ) % 2,
					5 => 0 === ( $x * $y ) % 2 + ( $x * $y ) % 3,
					6 => 0 === ( ( $x * $y ) % 2 + ( $x * $y ) % 3 ) % 2,
					default => 0 === ( ( $x + $y ) % 2 + ( $x * $y ) % 3 ) % 2,
				};
				if ( $flip ) {
					$this->modules[ $y ][ $x ] = ! $this->modules[ $y ][ $x ];
				}
			}
		}
	}

	/**
	 * Penalty score of the current matrix (lower scans better).
	 */
	private function penalty(): int {
		$size    = $this->size;
		$score   = 0;
		$dark    = 0;
		$pattern = array( '10111010000', '00001011101' );
		for ( $line = 0; $line < 2; $line++ ) {
			for ( $a = 0; $a < $size; $a++ ) {
				$run  = 0;
				$prev = null;
				$text = '';
				for ( $b = 0; $b < $size; $b++ ) {
					$value = 0 === $line ? $this->modules[ $a ][ $b ] : $this->modules[ $b ][ $a ];
					$text .= $value ? '1' : '0';
					if ( $value === $prev ) {
						++$run;
					} else {
						$score += $run >= 5 ? $run - 2 : 0;
						$run    = 1;
						$prev   = $value;
					}
				}
				$score += $run >= 5 ? $run - 2 : 0;
				foreach ( $pattern as $p ) {
					$score += 40 * substr_count( $text, $p );
				}
			}
		}
		for ( $y = 0; $y < $size; $y++ ) {
			for ( $x = 0; $x < $size; $x++ ) {
				$value = $this->modules[ $y ][ $x ];
				$dark += $value ? 1 : 0;
				if ( $x < $size - 1 && $y < $size - 1 && $value === $this->modules[ $y ][ $x + 1 ] && $value === $this->modules[ $y + 1 ][ $x ] && $value === $this->modules[ $y + 1 ][ $x + 1 ] ) {
					$score += 3;
				}
			}
		}
		$percent = intdiv( $dark * 100, $size * $size );
		return $score + 10 * intdiv( abs( $percent - 50 ), 5 );
	}
}
