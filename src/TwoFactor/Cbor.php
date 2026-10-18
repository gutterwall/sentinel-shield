<?php
/**
 * Minimal CBOR decoder for WebAuthn.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\TwoFactor;

defined( 'ABSPATH' ) || exit;

/**
 * Decodes the subset of CBOR (RFC 8949) that WebAuthn uses: unsigned and
 * negative integers, byte and text strings, arrays, maps, and the simple
 * values false, true and null. Indefinite lengths, tags and floats are
 * rejected; authenticators do not send them in attestation objects or keys.
 */
final class Cbor {

	/**
	 * Read position.
	 *
	 * @var int
	 */
	private int $pos = 0;

	/**
	 * Constructor.
	 *
	 * @param string $data CBOR bytes.
	 */
	private function __construct( private string $data ) {}

	/**
	 * Decodes one item from the start of $data.
	 *
	 * @param string   $data     CBOR bytes.
	 * @param int|null $consumed Set to the number of bytes the item used.
	 * @return mixed
	 * @throws \InvalidArgumentException On malformed or unsupported input.
	 */
	public static function decode( string $data, ?int &$consumed = null ): mixed {
		$reader   = new self( $data );
		$value    = $reader->item( 0 );
		$consumed = $reader->pos;
		return $value;
	}

	/**
	 * Reads one item.
	 *
	 * @param int $depth Nesting depth.
	 * @return mixed
	 * @throws \InvalidArgumentException On malformed input.
	 */
	private function item( int $depth ): mixed {
		if ( $depth > 16 ) {
			throw new \InvalidArgumentException( 'CBOR nested too deeply' );
		}
		$head  = ord( $this->take( 1 ) );
		$major = $head >> 5;
		$info  = $head & 0x1f;
		if ( 7 === $major ) {
			$simple = array(
				20 => false,
				21 => true,
				22 => null,
			);
			if ( ! array_key_exists( $info, $simple ) ) {
				throw new \InvalidArgumentException( 'Unsupported CBOR simple value' );
			}
			return $simple[ $info ];
		}
		$len = $this->length( $info );
		switch ( $major ) {
			case 0:
				return $len;
			case 1:
				return -1 - $len;
			case 2:
				return $this->take( $len );
			case 3:
				return $this->take( $len );
			case 4:
				$out = array();
				for ( $i = 0; $i < $len; $i++ ) {
					$out[] = $this->item( $depth + 1 );
				}
				return $out;
			case 5:
				$out = array();
				for ( $i = 0; $i < $len; $i++ ) {
					$key = $this->item( $depth + 1 );
					if ( ! is_int( $key ) && ! is_string( $key ) ) {
						throw new \InvalidArgumentException( 'Unsupported CBOR map key' );
					}
					$out[ $key ] = $this->item( $depth + 1 );
				}
				return $out;
			default:
				throw new \InvalidArgumentException( 'Unsupported CBOR type (tags are not used by WebAuthn)' );
		}
	}

	/**
	 * Reads the length or value that follows a head byte.
	 *
	 * @param int $info Additional information bits.
	 * @throws \InvalidArgumentException On indefinite or oversized lengths.
	 */
	private function length( int $info ): int {
		if ( $info < 24 ) {
			return $info;
		}
		$bytes = array(
			24 => 1,
			25 => 2,
			26 => 4,
			27 => 8,
		);
		if ( ! isset( $bytes[ $info ] ) ) {
			throw new \InvalidArgumentException( 'Unsupported CBOR length' );
		}
		$value = 0;
		foreach ( str_split( $this->take( $bytes[ $info ] ) ) as $byte ) {
			$value = ( $value << 8 ) | ord( $byte );
		}
		if ( $value < 0 || $value > 0x7fffffff ) {
			throw new \InvalidArgumentException( 'CBOR value too large' );
		}
		return $value;
	}

	/**
	 * Takes bytes from the input.
	 *
	 * @param int $n Count.
	 * @throws \InvalidArgumentException When the input ends early.
	 */
	private function take( int $n ): string {
		if ( $n < 0 || $this->pos + $n > strlen( $this->data ) ) {
			throw new \InvalidArgumentException( 'CBOR input ends early' );
		}
		$out        = substr( $this->data, $this->pos, $n );
		$this->pos += $n;
		return $out;
	}
}
