<?php
/**
 * Concurrency test over real HTTP: simultaneous requests race for the same
 * single-use secret, and exactly one may win.
 *
 *   backup code      the same backup code sent to three pending logins of one
 *                    account, several times each, at once
 *   authenticator    the same authenticator code (replay-protected step), likewise
 *   passkey          one signed passkey response submitted several times at once
 *   confirmation     "Confirm it is you" with the same backup code, at once
 *   wrong passwords  simultaneous guesses from one IP: no more are checked than
 *                    the limit allows
 *   Cloudflare       simultaneous WP-CLI syncs and confirmation checks of the
 *                    Cloudflare list (against a stand-in API): one update at a
 *                    time, every sync done, the state matches the list
 *
 * Usage: php bin/race-test.php <wordpress-path> <site-url> [workers=8]
 *
 * The site must serve at least <workers> requests in parallel (PHP_CLI_SERVER_WORKERS,
 * pm.max_children) and trust X-Forwarded-For from 127.0.0.1 (the test sets
 * this). It installs bin/race-barrier.php as a must-use plugin while it runs,
 * which holds the racing requests until all of them have arrived, and
 * bin/race-cloudflare.php, the stand-in for Cloudflare's API.
 * DESTRUCTIVE: creates users and changes settings. Use a throwaway site only.
 * Needs wp-cli and PHP's curl and openssl extensions.
 *
 * @package SentinelShield
 */

// phpcs:disable -- Developer tool, not shipped in the plugin zip.

if ( $argc < 3 ) {
	fwrite( STDERR, "Usage: php bin/race-test.php <wordpress-path> <site-url> [workers=8]\n" );
	exit( 2 );
}
$wp_path = rtrim( $argv[1], '/' );
$url     = rtrim( $argv[2], '/' );
$workers = max( 2, (int) ( $argv[3] ?? 8 ) );
const RACE_PASS = 'Race-pass-4821-zq';

define( 'ABSPATH', $wp_path . '/' );
require dirname( __DIR__ ) . '/src/TwoFactor/Totp.php';
use SentinelShield\TwoFactor\Totp;

$failed = 0;
$pass   = static function ( string $what ): void {
	echo "  ok   $what\n";
};
$fail   = static function ( string $what ) use ( &$failed ): void {
	echo "  FAIL $what\n";
	++$failed;
};

/** Runs wp-cli; returns its output (dies on error). */
function wp( string $args ): string {
	global $wp_path;
	// Standard error is kept apart: warnings (a missing sendmail) must not end up in parsed output.
	$err = (string) tempnam( sys_get_temp_dir(), 'race' );
	exec( 'wp --path=' . escapeshellarg( $wp_path ) . ' ' . $args . ' 2>' . escapeshellarg( $err ), $out, $code );
	$errors = (string) file_get_contents( $err );
	unlink( $err );
	if ( 0 !== $code ) {
		fwrite( STDERR, "wp $args failed:\n" . implode( "\n", $out ) . "\n" . $errors );
		exit( 1 );
	}
	return trim( implode( "\n", $out ) );
}

/** Runs PHP inside WordPress with the plugin's classes. */
function wp_php( string $code ): string {
	$code = 'use SentinelShield\Plugin; use SentinelShield\TwoFactor\UserTwoFactor; use SentinelShield\TwoFactor\Totp; use SentinelShield\TwoFactor\WebAuthn; $c = Plugin::instance()->container(); $u = $c->get( UserTwoFactor::class ); ' . $code;
	return wp( 'eval ' . escapeshellarg( $code ) );
}

function b64u( string $bytes ): string {
	return rtrim( strtr( base64_encode( $bytes ), '+/', '-_' ), '=' );
}

/** A browser: its cookies and the IP it appears to come from. */
final class Browser {
	/** @var array<string, string> */
	public array $cookies = array();

	public function __construct( public string $ip ) {}

	public function header(): string {
		return implode( '; ', array_map( static fn( $k, $v ) => "$k=$v", array_keys( $this->cookies ), $this->cookies ) );
	}

	public function take( string $headers ): void {
		foreach ( preg_split( '/\r?\n/', $headers ) as $line ) {
			if ( preg_match( '/^set-cookie:\s*([^=;]+)=([^;]*)(.*)$/i', $line, $m ) ) {
				$gone = 'deleted' === $m[2] || preg_match( '/max-age=0|expires=[^;]*19[789]\d/i', $m[3] );
				if ( $gone ) {
					unset( $this->cookies[ $m[1] ] );
				} else {
					$this->cookies[ $m[1] ] = $m[2];
				}
			}
		}
	}

	public function logged_in(): bool {
		foreach ( array_keys( $this->cookies ) as $name ) {
			if ( str_starts_with( $name, 'wordpress_logged_in_' ) ) {
				return true;
			}
		}
		return false;
	}
}

/**
 * Sends requests; more than one are sent at once and held by the barrier
 * until all have arrived.
 *
 * @param list<array{0:Browser, 1:string, 2:?array}> $requests Browser, path, POST fields (null = GET).
 * @return list<array{code:int, headers:string, body:string}>
 */
function http( array $requests, string $barrier = '' ): array {
	global $url;
	$multi   = curl_multi_init();
	$handles = array();
	$name    = $barrier . '-' . bin2hex( random_bytes( 4 ) );
	foreach ( $requests as $i => [ $browser, $path, $post ] ) {
		$h       = curl_init( $url . $path );
		$headers = array( 'X-Forwarded-For: ' . $browser->ip, 'Cookie: ' . $browser->header() );
		if ( count( $requests ) > 1 ) {
			$headers[] = 'X-Race-Barrier: ' . $name . '/' . count( $requests );
		}
		curl_setopt_array(
			$h,
			array(
				CURLOPT_RETURNTRANSFER => true,
				CURLOPT_HEADER         => true,
				CURLOPT_HTTPHEADER     => $headers,
				CURLOPT_TIMEOUT        => 60,
			)
		);
		if ( null !== $post ) {
			curl_setopt( $h, CURLOPT_POSTFIELDS, http_build_query( $post ) );
		}
		curl_multi_add_handle( $multi, $h );
		$handles[ $i ] = $h;
	}
	do {
		curl_multi_exec( $multi, $running );
		curl_multi_select( $multi, 0.05 );
	} while ( $running > 0 );
	$out = array();
	foreach ( $handles as $i => $h ) {
		$raw  = (string) curl_multi_getcontent( $h );
		$size = (int) curl_getinfo( $h, CURLINFO_HEADER_SIZE );
		$out[ $i ] = array(
			'code'    => (int) curl_getinfo( $h, CURLINFO_RESPONSE_CODE ),
			'headers' => substr( $raw, 0, $size ),
			'body'    => substr( $raw, $size ),
		);
		$requests[ $i ][0]->take( $out[ $i ]['headers'] );
		curl_multi_remove_handle( $multi, $h );
	}
	curl_multi_close( $multi );
	@unlink( sys_get_temp_dir() . '/sentinel-shield-race-' . $name );
	return $out;
}

/** Logs in with the password; returns the browser at the code screen. */
function start_login( string $user, string $ip ): Browser {
	$b = new Browser( $ip );
	$b->cookies['wordpress_test_cookie'] = 'WP%20Cookie%20check';
	$r = http( array( array( $b, '/wp-login.php', array( 'log' => $user, 'pwd' => RACE_PASS, 'testcookie' => '1', 'wp-submit' => 'Log In' ) ) ) )[0];
	if ( ! isset( $b->cookies['sentinel_shield_2fa'] ) ) {
		fwrite( STDERR, "Login of $user did not reach the code screen (HTTP {$r['code']}).\n" . $r['headers'] . substr( strip_tags( $r['body'] ), 0, 400 ) . "\n" );
		exit( 1 );
	}
	return $b;
}

/** Creates an account with an authenticator app and backup codes. */
function make_user( string $login, string $role = 'subscriber' ): array {
	wp( 'user delete ' . escapeshellarg( $login ) . ' --yes 2>/dev/null || true' );
	$id = (int) wp( 'user create ' . escapeshellarg( $login ) . ' ' . escapeshellarg( $login . '@example.org' ) . ' --role=' . $role . ' --user_pass=' . escapeshellarg( RACE_PASS ) . ' --porcelain' );
	if ( $id <= 0 ) {
		fwrite( STDERR, "Could not create $login.\n" );
		exit( 1 );
	}
	$json = wp_php( '$id = ' . $id . '; $s = $u->pending_secret( $id ); $t = time() - 300; $u->enable_totp( $id, Totp::code( $s, intdiv( $t, 30 ) ), $t ); echo json_encode( array( "secret" => $s, "backup" => $u->new_backup_codes( $id ) ) );' );
	$data = json_decode( $json, true );
	if ( ! is_array( $data ) || 10 > count( (array) ( $data['backup'] ?? array() ) ) ) {
		fwrite( STDERR, "Could not set up two-factor for $login: $json\n" );
		exit( 1 );
	}
	return array( $id, $data['secret'], $data['backup'] );
}

function remaining( int $id ): int {
	return (int) wp_php( 'echo $u->backup_remaining( ' . $id . ' );' );
}

echo "Race test: $url, $workers simultaneous requests\n";
$mu = $wp_path . '/wp-content/mu-plugins';
@mkdir( $mu, 0775, true );
copy( __DIR__ . '/race-barrier.php', "$mu/sentinel-shield-race-barrier.php" );
register_shutdown_function(
	static function () use ( $mu ): void {
		@unlink( "$mu/sentinel-shield-race-barrier.php" );
	}
);
wp( 'sentinel test-mode off' );
wp( 'sentinel settings-set proxy.mode custom' );
wp( 'sentinel settings-set proxy.header X-Forwarded-For' );
wp( 'sentinel settings-set proxy.trusted_cidrs 127.0.0.1' );
wp( 'sentinel settings-set twofa.required none' );
wp( 'sentinel login-attempts --clear' );
$ip = static fn( int $n ): string => '198.51.100.' . ( 120 + $n );
// Wrong codes count as failed logins: earlier runs may have locked these addresses out.
$unblock = static function () use ( $ip ): void {
	$list = var_export( array_merge( array_map( $ip, range( 0, 21 ) ), array( '198.51.100.250' ) ), true );
	wp_php( 'foreach ( ' . $list . ' as $a ) { $c->get( SentinelShield\Lockout\Unblocker::class )->unblock( $a, false, 0, 0, "cli" ); }' );
	wp( 'sentinel login-attempts --clear' );
};
$unblock();
register_shutdown_function( $unblock );

// Several pending logins of one account (three are kept per account), each
// sending the secret more than once.
$spread = static function ( string $login, array $post ) use ( $workers, $ip ): array {
	$logins = array();
	for ( $i = 0; $i < 3; $i++ ) {
		$logins[] = start_login( $login, $ip( $i ) );
	}
	$requests = array();
	for ( $i = 0; $i < $workers; $i++ ) {
		$requests[] = array( $logins[ $i % 3 ], '/wp-login.php?action=sentinel_shield_2fa', $post );
	}
	http( $requests, 'login' );
	return array_values( array_filter( $logins, static fn( Browser $b ): bool => $b->logged_in() ) );
};

echo "Backup code\n";
[ $id, , $backup ] = make_user( 'race_backup' );
$before            = remaining( $id );
$won               = $spread( 'race_backup', array( 'sentinel_shield_code' => $backup[0] ) );
$used              = $before - remaining( $id );
1 === count( $won ) && 1 === $used
	? $pass( "one backup code, $workers simultaneous submissions to three logins: exactly one login succeeded" )
	: $fail( sprintf( 'backup code: %d logins succeeded, %d codes consumed (want 1 and 1)', count( $won ), $used ) );

echo "Authenticator code\n";
[ $id, $secret ] = make_user( 'race_totp' );
$step            = intdiv( time(), 30 );
if ( time() % 30 > 25 ) {
	sleep( 30 - time() % 30 ); // Not at the very end of a step.
	$step = intdiv( time(), 30 );
}
$won = $spread( 'race_totp', array( 'sentinel_shield_code' => Totp::code( $secret, $step ) ) );
1 === count( $won )
	? $pass( "one authenticator code, $workers simultaneous submissions: exactly one login succeeded" )
	: $fail( sprintf( 'authenticator code: %d logins succeeded (want 1)', count( $won ) ) );

echo "Passkey\n";
[ $id ]  = make_user( 'race_passkey' );
$key     = openssl_pkey_new( array( 'private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1' ) );
$ec      = openssl_pkey_get_details( $key )['ec'];
$cred_id = random_bytes( 32 );
wp_php(
	sprintf(
		'$k = WebAuthn::cose_key( array( 1 => 2, 3 => -7, -1 => 1, -2 => hex2bin( "%s" ), -3 => hex2bin( "%s" ) ) ); $u->add_passkey( %d, array( "id" => "%s", "alg" => $k["alg"], "key" => $k["key"], "count" => 0, "uv" => true ), "race", time() );',
		bin2hex( str_pad( $ec['x'], 32, "\0", STR_PAD_LEFT ) ),
		bin2hex( str_pad( $ec['y'], 32, "\0", STR_PAD_LEFT ) ),
		$id,
		b64u( $cred_id )
	)
);
$browser = start_login( 'race_passkey', $ip( 10 ) );
$screen  = http( array( array( $browser, '/wp-login.php?action=sentinel_shield_2fa', null ) ) )[0]['body'];
preg_match( '/data-ss-passkey="get"[^>]*data-options="([^"]+)"/', $screen, $m ) || preg_match( '/data-options="([^"]+)"[^>]*data-ss-passkey="get"/', $screen, $m );
$options = json_decode( html_entity_decode( $m[1] ?? '', ENT_QUOTES ), true );
if ( ! is_array( $options ) ) {
	$fail( 'passkey: no passkey options on the code screen' );
} else {
	$origin = (string) preg_replace( '#^(https?://[^/]+).*$#', '$1', $url );
	$client = json_encode( array( 'type' => 'webauthn.get', 'challenge' => $options['challenge'], 'origin' => $origin ), JSON_UNESCAPED_SLASHES );
	$auth   = hash( 'sha256', $options['rpId'], true ) . chr( 0x05 ) . pack( 'N', 1 );
	openssl_sign( $auth . hash( 'sha256', $client, true ), $signature, $key, OPENSSL_ALGO_SHA256 );
	$response = json_encode( array( 'id' => b64u( $cred_id ), 'client' => b64u( $client ), 'auth' => b64u( $auth ), 'signature' => b64u( $signature ) ) );
	$requests = array();
	for ( $i = 0; $i < $workers; $i++ ) {
		$copy          = new Browser( $ip( 10 ) );
		$copy->cookies = $browser->cookies;
		$requests[]    = array( $copy, '/wp-login.php?action=sentinel_shield_2fa', array( 'sentinel_shield_passkey' => $response ) );
	}
	http( $requests, 'passkey' );
	$won = count( array_filter( array_column( $requests, 0 ), static fn( Browser $b ): bool => $b->logged_in() ) );
	1 === $won
		? $pass( "one signed passkey response, $workers simultaneous submissions: exactly one login succeeded" )
		: $fail( "passkey: $won logins succeeded with one response (want 1)" );
}

echo "Confirm it is you\n";
[ $id, $secret, $backup ] = make_user( 'race_confirm', 'administrator' );
$browser                  = start_login( 'race_confirm', $ip( 20 ) );
http( array( array( $browser, '/wp-login.php?action=sentinel_shield_2fa', array( 'sentinel_shield_code' => Totp::code( $secret, intdiv( time(), 30 ) ) ) ) ) );
if ( ! $browser->logged_in() ) {
	$fail( 'confirmation: could not log in' );
} else {
	$page = http( array( array( $browser, '/wp-admin/users.php?page=sentinel-shield-2fa', null ) ) )[0]['body'];
	preg_match( '/name="op" value="reauth".*?name="_wpnonce" value="([0-9a-f]+)"/s', $page, $m );
	$before   = remaining( $id );
	$requests = array();
	for ( $i = 0; $i < $workers; $i++ ) {
		$copy          = new Browser( $ip( 20 ) );
		$copy->cookies = $browser->cookies;
		$requests[]    = array( $copy, '/wp-admin/admin-post.php', array( 'action' => 'sentinel_shield_2fa_user', 'op' => 'reauth', '_wpnonce' => $m[1] ?? '', 'back' => '', 'password' => RACE_PASS, 'code' => $backup[0] ) );
	}
	http( $requests, 'confirm' );
	$used      = $before - remaining( $id );
	$confirmed = (int) wp_php( '$s = get_user_meta( ' . $id . ', UserTwoFactor::META . "reauth", true ); echo is_array( $s ) ? count( $s ) : 0;' );
	1 === $used && 1 === $confirmed
		? $pass( "one backup code, $workers simultaneous confirmations: consumed once, one session confirmed" )
		: $fail( "confirmation: backup codes consumed $used, sessions confirmed $confirmed (want 1 and 1)" );
}

echo "Wrong passwords\n";
wp( 'user delete race_bf --yes 2>/dev/null || true' );
wp( 'user create race_bf race_bf@example.org --role=subscriber --user_pass=' . escapeshellarg( RACE_PASS ) );
$max      = (int) wp( 'sentinel settings-get login.max_failures' );
$requests = array();
for ( $i = 0; $i < $workers; $i++ ) {
	$b                                   = new Browser( '198.51.100.250' );
	$b->cookies['wordpress_test_cookie'] = 'WP%20Cookie%20check';
	$requests[]                          = array( $b, '/wp-login.php', array( 'log' => 'race_bf', 'pwd' => 'wrong-' . $i, 'testcookie' => '1' ) );
}
$answers = http( $requests, 'guess' );
$errors  = count( array_filter( $answers, static fn( array $r ): bool => $r['code'] >= 500 || 0 === $r['code'] ) );
$checked = (int) wp_php( 'global $wpdb; echo (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$wpdb->base_prefix}sentinel_login_attempts WHERE ip = %s", inet_pton( "198.51.100.250" ) ) );' );
$late    = start_login_refused( '198.51.100.250' );
// Guesses that wait too long for the IP's turn are refused unchecked, so at
// most the limit is checked; the lockout follows exactly from the count.
$checked >= 1 && $checked <= $max && $late === ( $checked >= $max ) && 0 === $errors
	? $pass( "$workers simultaneous wrong passwords from one IP: $checked checked (limit $max), the rest refused unchecked; lockout " . ( $late ? 'on' : 'not reached' ) )
	: $fail( "wrong passwords: $checked checked (limit $max), $errors errors, right password afterwards " . ( $late ? 'refused' : 'accepted' ) );

/** Whether the right password from $ip is now refused. */
function start_login_refused( string $ip ): bool {
	$b = new Browser( $ip );
	$b->cookies['wordpress_test_cookie'] = 'WP%20Cookie%20check';
	$r = http( array( array( $b, '/wp-login.php', array( 'log' => 'race_bf', 'pwd' => RACE_PASS, 'testcookie' => '1' ) ) ) )[0];
	return ! $b->logged_in() && ( 403 === $r['code'] || false !== stripos( $r['body'], 'Too many' ) );
}

echo "Cloudflare\n";
$cf_dir = sys_get_temp_dir() . '/ss-race-cf-' . getmypid();
@mkdir( $cf_dir );
copy( __DIR__ . '/race-cloudflare.php', "$mu/sentinel-shield-race-cloudflare.php" );
putenv( "SENTINEL_SHIELD_RACE_CF=$cf_dir" );
register_shutdown_function(
	static function () use ( $mu, $cf_dir ): void {
		wp( 'sentinel settings-set cloudflare.sync 0' ); // Empties the stand-in list while it is still installed.
		putenv( 'SENTINEL_SHIELD_RACE_CF' );
		@unlink( "$mu/sentinel-shield-race-cloudflare.php" );
		wp( 'sentinel unblock 203.0.113.64 --include-ranges' );
		exec( 'rm -rf ' . escapeshellarg( $cf_dir ) );
	}
);
wp( 'sentinel block 203.0.113.64/28 --reason=race-cloudflare' );
wp( 'sentinel settings-set cloudflare.account_id ' . str_repeat( 'a', 32 ) );
wp( 'sentinel settings-set cloudflare.list_id ' . str_repeat( 'b', 32 ) );
wp_php( '$c->get( SentinelShield\Firewall\CloudflareSync::class )->set_token( "race-token" );' );
wp( 'sentinel settings-set cloudflare.sync 1' );
@unlink( "$cf_dir/calls.log" );
$syncs  = max( 2, min( $workers, 6 ) );
$checks = 2;
$env    = array_merge( getenv(), array( 'SENTINEL_SHIELD_RACE_CF' => $cf_dir, 'SENTINEL_SHIELD_RACE_CF_BARRIER' => (string) ( $syncs + $checks ) ) );
$procs  = array();
$streams = array();
for ( $i = 0; $i < $syncs + $checks; $i++ ) {
	$cmd     = $i < $syncs
		? array( 'wp', '--path=' . $wp_path, 'sentinel', 'cloudflare-sync' )
		: array( 'wp', '--path=' . $wp_path, 'eval', 'do_action( SentinelShield\Firewall\CloudflareSync::CHECK );' );
	$procs[] = proc_open( $cmd, array( 1 => array( 'pipe', 'w' ), 2 => array( 'pipe', 'w' ) ), $pipes, null, $env );
	$streams[] = $pipes;
}
$codes = array();
foreach ( $procs as $i => $proc ) {
	$text      = stream_get_contents( $streams[ $i ][1] ) . stream_get_contents( $streams[ $i ][2] );
	$codes[ $i ] = proc_close( $proc );
	if ( 0 !== $codes[ $i ] ) {
		echo '    worker ' . $i . ': ' . trim( $text ) . "\n";
	}
}
$calls = array_map( static fn( string $l ): array => (array) json_decode( $l, true ), array_filter( explode( "\n", (string) @file_get_contents( "$cf_dir/calls.log" ) ) ) );
$puts  = array_values( array_filter( $calls, static fn( array $c ): bool => 'PUT' === $c[0] ) );
$overlaps = 0;
foreach ( $puts as $a => $x ) {
	foreach ( $puts as $b => $y ) {
		$overlaps += $a < $b && $x[3] < $y[4] && $y[3] < $x[4] ? 1 : 0;
	}
}
$synced = count( array_filter( array_slice( $codes, 0, $syncs ), static fn( int $c ): bool => 0 === $c ) );
0 === $overlaps && $synced === $syncs && count( $puts ) === $syncs
	? $pass( "$syncs simultaneous syncs and $checks confirmation checks: " . count( $puts ) . ' uploads, one at a time, every sync done' )
	: $fail( "Cloudflare: $overlaps overlapping uploads, $synced of $syncs syncs done, " . count( $puts ) . ' uploads' );
wp_php( '$c->get( SentinelShield\Firewall\CloudflareSync::class )->check_operation();' );
$state = json_decode( wp_php( 'echo wp_json_encode( SentinelShield\Firewall\CloudflareSync::state() );' ), true );
$held  = (array) json_decode( (string) @file_get_contents( "$cf_dir/list.json" ), true );
'active' === ( $state['status'] ?? '' ) && (int) ( $state['count'] ?? -1 ) === count( $held ) && count( $held ) > 0
	? $pass( 'Cloudflare: the state says active with ' . count( $held ) . ' items, as the list holds' )
	: $fail( 'Cloudflare: state ' . ( $state['status'] ?? '?' ) . ' with ' . ( $state['count'] ?? '?' ) . ' items, the list holds ' . count( $held ) );

foreach ( array( 'race_backup', 'race_totp', 'race_passkey', 'race_confirm', 'race_bf' ) as $login ) {
	wp( 'user delete ' . $login . ' --yes' );
}
echo $failed ? "Race test FAILED ($failed).\n" : "Race test passed.\n";
exit( $failed ? 1 : 0 );
