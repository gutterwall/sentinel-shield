<?php
/**
 * Deliberate defects for bin/mutation-test.php: each entry changes one
 * security decision (a comparison, an expiry check, a capability or nonce
 * check, a replay or lock guard) and names the tests that must notice.
 * A mutant the tests do not notice ("survived") fails the run.
 *
 * Fields: file, find (must occur exactly once), replace, why, and the tests
 * to run: integration (a --filter for the integration suite; the whole unit
 * suite always runs too). "also" changes more files in the same mutant
 * (file => [find, replace]), for checks that back each other up.
 *
 * @package SentinelShield
 */

// phpcs:disable -- Test data.

$two_factor = 'TwoFactorTest|ReviewRegressionTest|WebAuthnTest|PentestRegressionTest';
$firewall   = 'EarlyGateTest|RepositoryGateTest|PentestRegressionTest|AdminAllowlistTest|BruteForceTest|ReviewRegressionTest';

return array(
	// Authorization: capability and nonce checks.
	array(
		'file'        => 'src/Admin/View.php',
		'find'        => "if ( ! current_user_can( '' === \$cap ? Admin::cap() : \$cap ) ) {",
		'replace'     => 'if ( false ) {',
		'why'         => 'admin actions skip the capability check',
		'integration' => 'AdminAuthorizationTest',
	),
	array(
		'file'        => 'src/Admin/View.php',
		'find'        => "\t\tcheck_admin_referer( \$nonce_action );",
		'replace'     => '',
		'why'         => 'admin actions skip the nonce check',
		'integration' => 'AdminAuthorizationTest',
	),
	array(
		'file'        => 'src/Admin/Actions.php',
		'find'        => "View::guard( 'sentinel_shield_save_site_settings', 'manage_options' );",
		'replace'     => "View::guard( 'sentinel_shield_save_site_settings', 'edit_posts' );",
		'why'         => 'per-site settings need only edit_posts',
		'integration' => 'AdminAuthorizationTest',
	),
	array(
		'file'        => 'src/Admin/Actions.php',
		'find'        => "View::guard( 'sentinel_shield_server' );",
		'replace'     => "View::guard( 'sentinel_shield_server', 'read' );",
		'why'         => 'Cloudflare token and server settings open to any account',
		'integration' => 'AdminAuthorizationTest',
	),
	array(
		'file'        => 'src/Admin/TwoFactorPage.php',
		'find'        => "\t\tif ( ! is_user_logged_in() ) {\n\t\t\twp_die( esc_html__( 'You must be logged in.', 'sentinel-shield' ), '', array( 'response' => 403 ) );\n\t\t}\n",
		'replace'     => '',
		'why'         => 'the two-factor page handler accepts visitors who are not logged in',
		'integration' => 'AdminAuthorizationTest',
	),
	array(
		'file'        => 'src/Admin/TwoFactorPage.php',
		'find'        => "|| ! current_user_can( 'edit_user', \$user_id ) ||",
		'replace'     => '||',
		'why'         => 'anyone can reset another account\'s two-factor from the profile form',
		'integration' => 'AdminAuthorizationTest',
	),
	array(
		'file'        => 'src/Admin/TwoFactorPage.php',
		'find'        => '|| ! self::reset_password_ok() ) {',
		'replace'     => ') {',
		'why'         => 'a two-factor reset does not need the resetting user\'s password',
		'integration' => 'AdminAuthorizationTest',
	),
	array(
		'file'        => 'src/Admin/RulesPage.php',
		'find'        => "\t\tif ( ! current_user_can( Admin::cap() ) ) {\n\t\t\twp_die( esc_html__( 'You do not have permission to do that.', 'sentinel-shield' ), '', array( 'response' => 403 ) );\n\t\t}\n\t\tcheck_admin_referer( 'bulk-sentinel_rules' );",
		'replace'     => "\t\tcheck_admin_referer( 'bulk-sentinel_rules' );",
		'why'         => 'bulk rule deletion skips the capability check',
		'integration' => 'AdminAuthorizationTest',
	),
	array(
		'file'        => 'src/Lockdown/Hardening.php',
		'find'        => "if ( ! is_user_logged_in() || ! current_user_can( 'activate_plugins' ) ) {",
		'replace'     => 'if ( ! is_user_logged_in() ) {',
		'why'         => 'any logged-in account may deactivate the plugin',
		'integration' => 'AdminAuthorizationTest|LockdownTest',
	),

	// Two-factor codes: windows, replay, single use, expiry, limits.
	array(
		'file'        => 'src/TwoFactor/Totp.php',
		'find'        => '&& $step > $last_step',
		'replace'     => '&& $step >= $last_step',
		'why'         => 'an authenticator code can be used twice',
		'integration' => $two_factor,
	),
	array(
		'file'        => 'src/TwoFactor/Totp.php',
		'find'        => 'array( $current - 1, $current, $current + 1 )',
		'replace'     => 'array( $current - 2, $current - 1, $current, $current + 1, $current + 2 )',
		'why'         => 'authenticator codes stay valid twice as long',
		'integration' => $two_factor,
	),
	array(
		'file'        => 'src/TwoFactor/UserTwoFactor.php',
		'find'        => "\t\tunset( \$hashes[ \$match ] );",
		'replace'     => '',
		'why'         => 'a backup code can be used again',
		'integration' => $two_factor,
	),
	array(
		'file'        => 'src/TwoFactor/TwoFactorLogin.php',
		'find'        => "isset( \$c['hash'] ) && (int) ( \$c['expires'] ?? 0 ) >= \$now",
		'replace'     => "isset( \$c['hash'] )",
		'why'         => 'a pending login never expires',
		'integration' => $two_factor,
	),
	array(
		'file'        => 'src/TwoFactor/TwoFactorLogin.php',
		'find'        => "if ( \$pending['tries'] >= self::MAX_TRIES ) {",
		'replace'     => "if ( \$pending['tries'] > self::MAX_TRIES ) {",
		'why'         => 'one more wrong code than allowed per login',
		'integration' => $two_factor,
	),
	array(
		'file'        => 'src/TwoFactor/TwoFactorLogin.php',
		'find'        => "|| count( \$budget['wrong'] ) >= self::WRONG_PER_HOUR ) {",
		'replace'     => "|| count( \$budget['wrong'] ) > self::WRONG_PER_HOUR ) {",
		'why'         => 'the hourly limit of wrong codes is off by one',
		'integration' => $two_factor,
	),
	array(
		'file'        => 'src/TwoFactor/TwoFactorLogin.php',
		'find'        => "|| (int) \$parts[1] < \$now ||",
		'replace'     => '||',
		'why'         => 'an expired "trust this browser" cookie still skips the code',
		'integration' => $two_factor,
	),
	array(
		'file'        => 'src/TwoFactor/UserTwoFactor.php',
		'find'        => "is_array( \$d ) && (int) ( \$d['expires'] ?? 0 ) > \$now",
		'replace'     => 'is_array( $d )',
		'why'         => 'trusted browsers never expire',
		'integration' => $two_factor,
	),
	array(
		'file'        => 'src/TwoFactor/UserTwoFactor.php',
		'find'        => "?? 0 ) > \$now - self::REAUTH_TTL;",
		'replace'     => '?? 0 ) > 0;',
		'why'         => 'an identity confirmation never expires',
		'integration' => $two_factor,
	),
	array(
		'file'        => 'src/Admin/TwoFactorPage.php',
		'find'        => "(int) ( \$stored['expires'] ?? 0 ) >= time() ?",
		'replace'     => 'true ?',
		'why'         => 'an expired passkey confirmation challenge is accepted',
		'integration' => $two_factor,
	),
	array(
		'file'        => 'src/Admin/TwoFactorPage.php',
		'find'        => 'if ( count( $fails ) >= self::REAUTH_MAX ) {',
		'replace'     => 'if ( count( $fails ) > self::REAUTH_MAX ) {',
		'why'         => 'one more failed identity confirmation than allowed',
		'integration' => $two_factor,
	),

	// Passkeys (WebAuthn).
	array(
		'file'        => 'src/Admin/TwoFactorPage.php',
		'find'        => '$challenge, WebAuthn::UV_REQUIRED );',
		'replace'     => '$challenge );',
		'why'         => 'a touch-only key confirms identity without the password',
		'integration' => $two_factor,
	),
	array(
		'file'        => 'src/TwoFactor/TwoFactorLogin.php',
		'find'        => '$challenge, $this->passkey_uv() );',
		'replace'     => '$challenge );',
		'why'         => 'the login ignores the "require user verification" setting',
		'integration' => $two_factor,
	),
	array(
		'file'        => 'src/TwoFactor/WebAuthn.php',
		'find'        => 'if ( self::UV_REQUIRED === self::uv( $uv ) && ! ( $flags & self::FLAG_UV ) ) {',
		'replace'     => 'if ( false ) {',
		'why'         => 'the user-verified flag is never checked',
		'integration' => $two_factor,
	),
	array(
		'file'        => 'src/TwoFactor/WebAuthn.php',
		'find'        => "&& \$auth['count'] <= (int) \$stored['count'] ) {",
		'replace'     => "&& \$auth['count'] < (int) \$stored['count'] ) {",
		'why'         => 'a cloned authenticator repeating its counter is accepted',
		'integration' => $two_factor,
	),
	array(
		'file'        => 'src/TwoFactor/WebAuthn.php',
		'find'        => "if ( ! in_array( strtolower( (string) ( \$client['origin'] ?? '' ) ), \$this->origins, true ) ) {",
		'replace'     => 'if ( false ) {',
		'why'         => 'passkey responses from another site are accepted',
		'integration' => $two_factor,
	),
	array(
		'file'        => 'src/TwoFactor/WebAuthn.php',
		'find'        => "if ( ! hash_equals( hash( 'sha256', \$this->rp_id, true ), substr( \$data, 0, 32 ) ) ) {",
		'replace'     => 'if ( false ) {',
		'why'         => 'keys scoped to another relying party are accepted',
		'integration' => $two_factor,
	),
	array(
		'file'        => 'src/TwoFactor/WebAuthn.php',
		'find'        => 'if ( ! ( $flags & self::FLAG_UP ) ) {',
		'replace'     => 'if ( false ) {',
		'why'         => 'responses without user presence are accepted',
		'integration' => $two_factor,
	),
	array(
		'file'        => 'src/TwoFactor/WebAuthn.php',
		'find'        => "if ( '' === \$challenge || ! hash_equals( \$challenge, (string) ( \$client['challenge'] ?? '' ) ) ) {",
		'replace'     => "if ( '' === \$challenge ) {",
		'why'         => 'a response signed for another challenge is accepted',
		'integration' => $two_factor,
	),
	array(
		'file'        => 'src/TwoFactor/TwoFactorLogin.php',
		'find'        => "\t\t\t\t\$pending['webauthn'] = WebAuthn::challenge();\n\t\t\t\t\$data ",
		'replace'     => "\t\t\t\t\$data ",
		'why'         => 'the login passkey challenge is not replaced after an attempt (replay)',
		'integration' => $two_factor,
	),

	// Brute force, rules and the firewalls.
	array(
		'file'        => 'src/Login/BruteForceGuard.php',
		'find'        => 'if ( $failures >= $max ) {',
		'replace'     => 'if ( $failures > $max ) {',
		'why'         => 'the lockout comes one failure late',
		'integration' => $firewall,
	),
	array(
		'file'        => 'src/Login/BruteForceGuard.php',
		'find'        => 'if ( $this->attempts->count_ip( $bin, $since ) >= $this->max_failures() ) {',
		'replace'     => 'if ( $this->attempts->count_ip( $bin, $since ) > $this->max_failures() ) {',
		'why'         => 'one more password guess than allowed is checked',
		'integration' => $firewall,
	),
	array(
		'file'        => 'src/Repository/BlockRepository.php',
		'find'        => 'AND ip_end >= UNHEX(%s) AND (expires_at IS NULL OR expires_at > %s)',
		'replace'     => 'AND ip_end >= UNHEX(%s) AND (expires_at IS NULL OR expires_at > %s OR 1 = 1)',
		'why'         => 'expired rules still match',
		'integration' => 'RepositoryGateTest',
	),
	array(
		'file'        => 'src/Firewall/Gate.php',
		'find'        => "if ( ! \$ignore_allowlist && \$this->rules->get( 'allow' )->contains( \$bin ) ) {",
		'replace'     => 'if ( false ) {',
		'why'         => 'the allowlist no longer wins over block rules',
		'integration' => $firewall,
	),
	array(
		'file'        => 'early-gate.php',
		'find'        => "|| (int) ( \$config['valid_until'] ?? 0 ) < time() ) {",
		'replace'     => ') {',
		'why'         => 'the early firewall enforces an expired snapshot',
		'integration' => 'EarlyGateTest',
	),
	array(
		'file'        => 'early-gate.php',
		'find'        => "if ( ! \$fallback && true === \$in_file( (string) ( \$config['allow_file'] ?? '' ), \$client ) ) {",
		'replace'     => 'if ( false ) {',
		'why'         => 'the early firewall ignores the allowlist',
		'integration' => 'EarlyGateTest',
	),
	array(
		'file'        => 'early-gate.php',
		'find'        => 'if ( ! $fallback && true ===',
		'replace'     => 'if ( true ===',
		'why'         => 'a proxy\'s own address inherits allowlist privileges',
		'integration' => 'EarlyGateTest',
	),
	array(
		'file'        => 'early-gate.php',
		'find'        => "&& \$contains( \$trusted, \$remote ) ) {",
		'replace'     => ') {',
		'why'         => 'any visitor can choose their IP with a forwarding header',
		'integration' => 'EarlyGateTest',
	),
	array(
		'file'        => 'early-gate.php',
		'find'        => 'if ( strcmp( $bin, substr( $row, 0, $len ) ) < 0 ) {',
		'replace'     => 'if ( strcmp( $bin, substr( $row, 0, $len ) ) <= 0 ) {',
		'why'         => 'the first address of a blocked range is let through',
		'integration' => 'EarlyGateTest',
	),
	array(
		'file'        => 'src/Net/ClientIp.php',
		'find'        => "if ( ! \$result['remote_trusted'] ) {",
		'replace'     => 'if ( false ) {',
		'why'         => 'forwarding headers are believed from untrusted peers',
		'integration' => $firewall,
	),
	array(
		'file'        => 'src/Net/RangeMath.php',
		'find'        => '$out[] = array( $cursor, self::step( $cs, -1 ) );',
		'replace'     => '$out[] = array( $cursor, $cs );',
		'why'         => 'the first allowlisted address of an exemption stays blocked',
		'integration' => 'EarlyGateTest',
	),
	array(
		'file'        => 'src/Net/RangeMath.php',
		'find'        => '$cursor = self::step( $ce, 1 );',
		'replace'     => '$cursor = $ce;',
		'why'         => 'the last allowlisted address of an exemption stays blocked',
		'integration' => 'EarlyGateTest',
	),

	// Unlock links.
	array(
		'file'        => 'src/Repository/TokenRepository.php',
		'find'        => "'UPDATE %i SET used_at = %s WHERE token_hash = %s AND used_at IS NULL AND expires_at > %s',",
		'replace'     => "'UPDATE %i SET used_at = %s WHERE token_hash = %s AND expires_at > %s',",
		'why'         => 'an unlock link works more than once',
		'integration' => 'RepositoryGateTest|ReviewRegressionTest|PentestRegressionTest',
	),
	array(
		'file'        => 'src/Repository/TokenRepository.php',
		'find'        => "'UPDATE %i SET used_at = %s WHERE token_hash = %s AND used_at IS NULL AND expires_at > %s',",
		'replace'     => "'UPDATE %i SET used_at = %s WHERE token_hash = %s AND used_at IS NULL AND (expires_at > %s OR expires_at IS NOT NULL)',",
		'why'         => 'an expired unlock link still works',
		'integration' => 'RepositoryGateTest|ReviewRegressionTest|PentestRegressionTest',
	),
	array(
		'file'        => 'src/Unlock/UnlockService.php',
		'find'        => "if ( \$count >= (int) \$this->settings->get( 'unlock.max_requests_per_hour', 3 ) ) {",
		'replace'     => "if ( \$count > (int) \$this->settings->get( 'unlock.max_requests_per_hour', 3 ) ) {",
		'why'         => 'one more unlock email per hour than allowed',
		'integration' => 'RepositoryGateTest|ReviewRegressionTest|PentestRegressionTest',
	),

	// Locks, the private folder and publication.
	array(
		'file'        => 'src/Support/Mutex.php',
		'find'        => "\t\tif ( '0' === \$got ) {\n\t\t\treturn false;\n\t\t}",
		'replace'     => "\t\tif ( '0' === \$got ) {\n\t\t\treturn true;\n\t\t}",
		'why'         => 'a lock held by another request is treated as taken',
		'integration' => 'ReviewRegressionTest|TwoFactorTest|BruteForceTest',
	),
	array(
		'file'        => 'src/Support/Mutex.php',
		'find'        => 'if ( null !== $until && (int) $until < $now ) {',
		'replace'     => 'if ( null !== $until ) {',
		'why'         => 'a fallback lock row is taken over before its lease ends',
		'integration' => 'ReviewRegressionTest|PentestRegressionTest|RepositoryGateTest',
	),
	array(
		'file'        => 'src/Support/DataDir.php',
		'find'        => "'probe' === \$method         => \$age < self::PROBE_LIFE,",
		'replace'     => "'probe' === \$method         => true,",
		'why'         => 'evidence from an HTTP probe never goes stale',
		'integration' => 'EarlyGateTest',
	),
	array(
		'file'        => 'src/Firewall/EarlyGate.php',
		'find'        => 'if ( true !== DataDir::is_private() ) {',
		'replace'     => 'if ( false === DataDir::is_private() ) {',
		'why'         => 'an unverified data folder is used for the policy',
		'integration' => 'EarlyGateTest',
	),
	array(
		// Both defences at once: each alone already stops a short range file.
		'file'        => 'src/Firewall/FeedSnapshot.php',
		'find'        => "\$put = static fn( string \$bytes ): bool => '' === \$bytes || strlen( \$bytes ) === @fwrite( \$out, \$bytes );",
		'replace'     => "\$put = static fn( string \$bytes ): bool => '' === \$bytes || false !== @fwrite( \$out, \$bytes );",
		'also'        => array(
			'src/Firewall/EarlyGate.php' => array( "return pack( 'NN', \$n4, \$n6 ) === substr( \$head, 8 ) && (int) filesize( \$file ) === 16 + 8 * \$n4 + 32 * \$n6;", 'return true;' ),
		),
		'why'         => 'a range file cut short by a full disk is published',
		'integration' => 'EarlyGateTest',
	),
	array(
		'file'        => 'src/Firewall/EarlyGate.php',
		'find'        => '$block_set = RangeMath::subtract( IpRangeSet::from_pairs( $pairs ), $exempt );',
		'replace'     => '$block_set = IpRangeSet::from_pairs( $pairs );',
		'why'         => 'the published policy blocks allowlisted addresses',
		'integration' => 'EarlyGateTest',
	),
	array(
		'file'        => 'src/Firewall/CloudflareSync.php',
		'find'        => "'active'               => ! empty( \$state['count'] ),",
		'replace'     => "'active'               => false,",
		'why'         => 'Cloudflare lists with items are forgotten without being emptied',
		'integration' => 'EarlyGateTest|CloudflareContractTest',
	),
	array(
		'file'        => 'src/Login/AppPasswordPolicy.php',
		'find'        => 'if ( $max > 0 && $created > 0 && $created < $now - $max * DAY_IN_SECONDS ) {',
		'replace'     => 'if ( false ) {',
		'why'         => 'application passwords never expire',
		'integration' => 'RepositoryGateTest|BruteForceTest|PentestRegressionTest|ReviewRegressionTest|LockdownTest',
	),
	array(
		'file'        => 'src/Geo/LoginGeoGuard.php',
		'find'        => "\$out['allowed'] = 'allow' === \$mode ? \$listed : ! \$listed;",
		'replace'     => "\$out['allowed'] = 'allow' === \$mode ? ! \$listed : \$listed;",
		'why'         => 'the country allow and block lists are swapped',
		'integration' => 'GeoLoginTest',
	),
);
