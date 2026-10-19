<?php
/**
 * Fuzzing of everything that parses outside input.
 *
 * @package SentinelShield
 */

declare(strict_types=1);

namespace SentinelShield\Tests\Integration;

use SentinelShield\Feeds\FeedParser;
use SentinelShield\Firewall\FeedSnapshot;
use SentinelShield\Net\Cidr;
use SentinelShield\Net\ClientIp;
use SentinelShield\Net\IpRangeSet;
use SentinelShield\Net\PackedRangeSet;
use SentinelShield\Settings;
use SentinelShield\SettingsSchema;
use SentinelShield\TwoFactor\Cbor;
use SentinelShield\TwoFactor\WebAuthn;

/**
 * Review 5 (P1): random and mutated input for the CBOR decoder, WebAuthn
 * verification, feed parsers, snapshot reader, settings import, IP header
 * parsing and CIDR parsing. Each input must be refused (or accepted) cleanly:
 * only the documented exception, no PHP warning, notice or type error (the
 * test suite turns those into failures), within a time and memory budget.
 *
 * Iterations: FUZZ_ITERATIONS (default 300 per target); the seed is FUZZ_SEED,
 * or random and named in every failure so it can be replayed.
 */
final class FuzzTest extends \WP_UnitTestCase {

	private int $seed = 0;

	private int $rounds = 0;

	public function set_up(): void {
		parent::set_up();
		$this->seed   = (int) ( getenv( 'FUZZ_SEED' ) ?: random_int( 1, PHP_INT_MAX >> 1 ) );
		$this->rounds = (int) ( getenv( 'FUZZ_ITERATIONS' ) ?: ( self::measured() ? 30 : 300 ) );
		mt_srand( $this->seed );
	}

	/**
	 * Whether coverage is being measured (every line is far slower then): the
	 * fuzzing runs fewer rounds and gives each case more time.
	 */
	private static function measured(): bool {
		return ( function_exists( 'xdebug_code_coverage_started' ) && xdebug_code_coverage_started() ) || ( extension_loaded( 'pcov' ) && ini_get( 'pcov.enabled' ) );
	}

	/**
	 * Random bytes (mt_rand, so the seed replays them).
	 *
	 * @param int $n Length.
	 */
	private static function bytes( int $n ): string {
		$out = '';
		for ( $i = 0; $i < $n; $i++ ) {
			$out .= chr( mt_rand( 0, 255 ) );
		}
		return $out;
	}

	/**
	 * A copy of $data with a few random changes: flipped bits, inserted,
	 * deleted or duplicated bytes, truncation, or huge length prefixes.
	 *
	 * @param string $data Valid input.
	 */
	private static function mutate( string $data ): string {
		for ( $i = 0, $n = mt_rand( 1, 4 ); $i < $n; $i++ ) {
			$len = strlen( $data );
			$pos = $len ? mt_rand( 0, $len - 1 ) : 0;
			switch ( mt_rand( 0, 6 ) ) {
				case 0:
					if ( $len ) {
						$data[ $pos ] = chr( ord( $data[ $pos ] ) ^ ( 1 << mt_rand( 0, 7 ) ) );
					}
					break;
				case 1:
					$data = substr( $data, 0, $pos ) . self::bytes( mt_rand( 1, 8 ) ) . substr( $data, $pos );
					break;
				case 2:
					$data = substr( $data, 0, $pos ) . substr( $data, $pos + mt_rand( 1, 8 ) );
					break;
				case 3:
					$data = substr( $data, 0, $pos );
					break;
				case 4:
					$data = substr( $data, 0, $pos ) . substr( $data, $pos, 16 ) . substr( $data, $pos );
					break;
				case 5:
					// CBOR heads announcing enormous lengths or deep nesting.
					$data = substr( $data, 0, $pos ) . ( array( "\x5b\xff\xff\xff\xff\xff\xff\xff\xff", "\x9b\x00\x00\x00\x01\x00\x00\x00\x00", str_repeat( "\x81", 40 ), "\xbf", "\x7a\xff\xff\xff\xff" )[ mt_rand( 0, 4 ) ] ) . substr( $data, $pos );
					break;
				default:
					$data = strrev( $data );
			}
		}
		return $data;
	}

	/**
	 * Runs one fuzz case within budgets: $call may throw only $allowed.
	 *
	 * @param string                        $label   What and which case.
	 * @param callable                      $call    The call.
	 * @param list<class-string<\Throwable>> $allowed Exceptions that mean "refused".
	 */
	private function within_budget( string $label, callable $call, array $allowed ): void {
		$start  = microtime( true );
		$memory = memory_get_usage();
		try {
			$call();
		} catch ( \Throwable $e ) {
			$ok = false;
			foreach ( $allowed as $class ) {
				$ok = $ok || $e instanceof $class;
			}
			if ( ! $ok ) {
				$this->fail( sprintf( '%s (seed %d): %s: %s', $label, $this->seed, get_class( $e ), $e->getMessage() ) );
			}
		}
		$this->assertLessThan( self::measured() ? 20.0 : 1.0, microtime( true ) - $start, "$label (seed {$this->seed}): too slow" );
		$this->assertLessThan( 32 * MB_IN_BYTES, memory_get_usage() - $memory, "$label (seed {$this->seed}): too much memory" );
	}

	public function test_cbor_decoder(): void {
		$valid = array(
			SoftAuthenticator::cbor( array( 'fmt' => 'none', 'attStmt' => array(), 'authData' => new CborBytes( str_repeat( 'a', 80 ) ) ) ),
			SoftAuthenticator::cbor( array( 1 => 2, 3 => -7, -1 => 1, -2 => new CborBytes( str_repeat( 'x', 32 ) ), -3 => new CborBytes( str_repeat( 'y', 32 ) ) ) ),
			SoftAuthenticator::cbor( array( array( array( array( 1, 2, 3 ) ) ) ) ),
		);
		for ( $i = 0; $i < $this->rounds; $i++ ) {
			$input = 0 === $i % 5 ? self::bytes( mt_rand( 0, 200 ) ) : self::mutate( $valid[ $i % 3 ] );
			$this->within_budget( "CBOR case $i", static fn() => Cbor::decode( $input ), array( \InvalidArgumentException::class ) );
		}
		// The limits themselves.
		$this->within_budget( 'CBOR deep nesting', static fn() => Cbor::decode( str_repeat( "\x81", 100000 ) . "\x01" ), array( \InvalidArgumentException::class ) );
		$this->within_budget( 'CBOR huge string', static fn() => Cbor::decode( "\x5a\x7f\xff\xff\xff" . 'abc' ), array( \InvalidArgumentException::class ) );
		$this->within_budget( 'CBOR huge array', static fn() => Cbor::decode( "\x9a\x7f\xff\xff\xff\x01" ), array( \InvalidArgumentException::class ) );
	}

	public function test_webauthn_verification(): void {
		$rp      = new WebAuthn( 'fuzz.example', array( 'https://fuzz.example' ), 'Fuzz' );
		$key     = new SoftAuthenticator( WebAuthn::ALG_ES256, 'fuzz.example', 'https://fuzz.example' );
		$reg     = WebAuthn::challenge();
		$created = $key->register( $reg );
		$stored  = $rp->verify_registration( WebAuthn::unb64u( $created['client'] ), WebAuthn::unb64u( $created['attestation'] ), $reg );
		for ( $i = 0; $i < $this->rounds; $i++ ) {
			$challenge = WebAuthn::challenge();
			$response  = $key->sign( $challenge );
			$field     = array( 'client', 'auth', 'signature' )[ $i % 3 ];
			$parts     = array_map( array( WebAuthn::class, 'unb64u' ), $response );
			$parts[ $field ] = self::mutate( $parts[ $field ] );
			$this->within_budget(
				"WebAuthn assertion case $i ($field)",
				function () use ( $rp, $stored, $parts, $challenge ): void {
					$rp->verify_assertion( $stored, $parts['client'], $parts['auth'], $parts['signature'], $challenge );
					$this->fail( 'a mutated assertion was accepted' );
				},
				array( \RuntimeException::class )
			);
			$which = $i % 2 ? 'client' : 'attestation';
			$reg_parts           = array(
				'client'      => WebAuthn::unb64u( $created['client'] ),
				'attestation' => WebAuthn::unb64u( $created['attestation'] ),
			);
			$reg_parts[ $which ] = self::mutate( $reg_parts[ $which ] );
			$this->within_budget( "WebAuthn registration case $i ($which)", static fn() => $rp->verify_registration( $reg_parts['client'], $reg_parts['attestation'], $reg ), array( \RuntimeException::class ) );
		}
		// The COSE key converter with random maps.
		for ( $i = 0; $i < $this->rounds; $i++ ) {
			$map = array(
				1  => mt_rand( -2, 4 ),
				3  => array( -7, -8, -257, 0, mt_rand( -300, 300 ) )[ mt_rand( 0, 4 ) ],
				-1 => mt_rand( 0, 1 ) ? mt_rand( -2, 7 ) : self::bytes( mt_rand( 0, 300 ) ),
				-2 => self::bytes( mt_rand( 0, 40 ) ),
				-3 => mt_rand( 0, 1 ) ? self::bytes( mt_rand( 0, 40 ) ) : array(),
			);
			$this->within_budget( "COSE case $i", static fn() => WebAuthn::cose_key( $map ), array( \RuntimeException::class ) );
		}
	}

	public function test_feed_parsers(): void {
		$samples = array(
			'lines'         => "# comment\n192.0.2.0/24 ; note\n2001:db8::/32\n198.51.100.7\n",
			'spamhaus_json' => "{\"cidr\":\"192.0.2.0/24\",\"sblid\":\"SBL1\",\"rir\":\"arin\"}\n{\"type\":\"metadata\"}\n",
			'dshield'       => "#\n192.0.2.0\t192.0.2.255\t24\t5\n",
		);
		foreach ( $samples as $format => $body ) {
			for ( $i = 0; $i < $this->rounds; $i++ ) {
				$input = $i % 4 ? self::mutate( str_repeat( $body, mt_rand( 1, 20 ) ) ) : self::bytes( mt_rand( 0, 2000 ) );
				$this->within_budget(
					"feed $format case $i",
					function () use ( $format, $input ): void {
						$result = FeedParser::parse( $format, $input );
						foreach ( $result['ranges'] as $cidr ) {
							$this->assertTrue( FeedParser::is_acceptable( $cidr ) );
						}
					},
					array()
				);
			}
		}
		// A body far larger than any real list is cut off, not loaded whole into ranges.
		$huge = str_repeat( "10.0.0.0/8\n", self::measured() ? 1000 : 300000 );
		$this->within_budget( 'a very long feed', static fn() => FeedParser::parse( 'lines', $huge ), array() );
	}

	public function test_snapshot_reader(): void {
		// In a folder of its own: the writer protects its folder with .htaccess and index.php.
		$dir  = get_temp_dir() . 'ss-fuzz-' . wp_generate_password( 6, false );
		$path = $dir . '/snapshot.bin';
		$valid = IpRangeSet::from_strings( array( '192.0.2.0/24', '198.51.100.0/25', '2001:db8::/48' ) );
		$this->assertTrue( FeedSnapshot::write( $valid, $path ) );
		$good = (string) file_get_contents( $path );
		try {
			for ( $i = 0; $i < $this->rounds; $i++ ) {
				file_put_contents( $path, $i % 5 ? self::mutate( $good ) : self::bytes( mt_rand( 0, 100 ) ) );
				$this->within_budget(
					"snapshot case $i",
					function () use ( $path ): void {
						$set = FeedSnapshot::read_set( $path );
						if ( null !== $set ) {
							$set->contains( (string) inet_pton( '192.0.2.1' ) );
							$set->contains( (string) inet_pton( '2001:db8::1' ) );
						}
					},
					array()
				);
			}
			// A header claiming billions of ranges is refused without allocating them.
			file_put_contents( $path, FeedSnapshot::MAGIC . pack( 'NN', 0xffffffff, 0xffffffff ) );
			$this->within_budget( 'snapshot with huge counts', fn() => $this->assertNull( FeedSnapshot::read_set( $path ) ), array() );
		} finally {
			array_map( 'unlink', array_merge( (array) glob( $dir . '/*' ), (array) glob( $dir . '/.htaccess' ) ) );
			@rmdir( $dir ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		}
		// Stored packed sets (options) with damaged content.
		for ( $i = 0; $i < $this->rounds; $i++ ) {
			$storage = array(
				4 => base64_encode( self::bytes( mt_rand( 0, 50 ) ) ), // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
				6 => mt_rand( 0, 1 ) ? '***' : base64_encode( self::bytes( mt_rand( 0, 100 ) ) ), // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
			);
			$this->within_budget( "packed set case $i", static fn() => PackedRangeSet::from_storage( $storage )->contains( (string) inet_pton( '10.0.0.1' ) ), array() );
		}
	}

	/**
	 * A random JSON-like value.
	 *
	 * @param int $depth Depth left.
	 */
	private static function value( int $depth = 3 ): mixed {
		switch ( mt_rand( 0, $depth > 0 ? 7 : 5 ) ) {
			case 0:
				return mt_rand( -100000, 100000 );
			case 1:
				return mt_rand( 0, 1 ) === 1;
			case 2:
				return null;
			case 3:
				return mt_rand() / mt_getrandmax() * 1e6;
			case 4:
				return self::bytes( mt_rand( 0, 30 ) );
			case 5:
				return array( 'off', 'on', 'all', 'none', '1', '0', 'yes', '', '203.0.113.0/24', "<script>x</script>", str_repeat( 'a', 5000 ) )[ mt_rand( 0, 10 ) ];
			default:
				$out = array();
				for ( $i = 0, $n = mt_rand( 0, 4 ); $i < $n; $i++ ) {
					$out[ mt_rand( 0, 1 ) ? (string) mt_rand( 0, 9 ) : self::bytes( 3 ) ] = self::value( $depth - 1 );
				}
				return $out;
		}
	}

	public function test_settings_import(): void {
		$fields = SettingsSchema::fields();
		for ( $i = 0; $i < $this->rounds; $i++ ) {
			$input = array();
			foreach ( $fields as $field ) {
				if ( mt_rand( 0, 3 ) ) {
					Settings::set_path( $input, $field['key'], self::value() );
				}
			}
			$input[ self::bytes( 4 ) ] = self::value();
			$this->within_budget(
				"settings import case $i",
				function () use ( $input, $fields ): void {
					[ $out ] = SettingsSchema::sanitize_all( $input );
					foreach ( $fields as $field ) {
						$value = Settings::get_path( $out, $field['key'] );
						$type  = $field['type'];
						$ok    = match ( $type ) {
							'checkbox' => is_bool( $value ),
							'number'   => is_int( $value ) && $value >= (int) ( $field['min'] ?? PHP_INT_MIN ) && $value <= (int) ( $field['max'] ?? PHP_INT_MAX ),
							'select'   => is_string( $value ) && array_key_exists( $value, $field['options'] ),
							default    => ! is_object( $value ),
						};
						$this->assertTrue( $ok, sprintf( '%s got %s (seed %d)', $field['key'], var_export( $value, true ), $this->seed ) );
					}
				},
				array()
			);
		}
	}

	public function test_ip_headers_and_cidrs(): void {
		$trusted = IpRangeSet::from_strings( array( '10.0.0.0/8', '127.0.0.1' ) );
		$pieces  = array( '203.0.113.5', '10.0.0.1', '2001:db8::1', '[2001:db8::2]:443', 'unknown', 'for=', 'for="[::1]"', ';', ',', ' ', '"', '999.1.1.1', '1.2.3.4:80', '::ffff:1.2.3.4', '%', "\0" );
		for ( $i = 0; $i < $this->rounds; $i++ ) {
			$header = '';
			for ( $j = 0, $n = mt_rand( 0, 12 ); $j < $n; $j++ ) {
				$header .= mt_rand( 0, 4 ) ? $pieces[ mt_rand( 0, count( $pieces ) - 1 ) ] : self::bytes( mt_rand( 1, 5 ) );
			}
			foreach ( array( array( 'custom', 'X-Forwarded-For' ), array( 'custom', 'Forwarded' ), array( 'cloudflare', 'CF-Connecting-IP' ), array( 'load_balancer', 'X-Forwarded-For' ) ) as [ $mode, $name ] ) {
				$server = array(
					'REMOTE_ADDR'                                            => mt_rand( 0, 3 ) ? '10.0.0.9' : self::bytes( 6 ),
					'HTTP_' . strtoupper( str_replace( '-', '_', $name ) ) => $header,
				);
				$this->within_budget(
					"client IP case $i ($mode)",
					function () use ( $server, $mode, $name, $trusted ): void {
						$ip = ( new ClientIp( $server, $mode, $name, $trusted ) )->resolve();
						$this->assertTrue( '' === $ip || false !== filter_var( $ip, FILTER_VALIDATE_IP ), "resolved to $ip" );
					},
					array()
				);
			}
			$text = mt_rand( 0, 1 ) ? self::mutate( '2001:db8::/48' ) : self::mutate( '192.0.2.0/24' );
			$this->within_budget(
				"CIDR case $i",
				function () use ( $text ): void {
					$cidr = Cidr::parse( $text );
					if ( null !== $cidr ) {
						$this->assertSame( $cidr->to_string(), Cidr::parse( $cidr->to_string() )->to_string() );
					}
					IpRangeSet::parse_lines( $text . "\n" . $text );
				},
				array()
			);
		}
	}
}
