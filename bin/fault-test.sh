#!/usr/bin/env bash
# Crash test: PHP workers are killed (SIGKILL, no cleanup at all) at each step
# of a policy publication, of a Cloudflare upload and while holding a lock;
# the next worker must find a complete, working policy, no false claim of
# success, and no stranded lock. Also checks a full disk (a file size limit).
#
# Usage: bin/fault-test.sh <wordpress-path> [site-url]
#   With site-url (the early firewall active, as in the smoke test), blocked
#   and unblocked addresses are also checked over HTTP after every crash.
#
# DESTRUCTIVE: changes settings and rules. Use a throwaway site only.
# Needs wp-cli and PHP's posix and pcntl extensions.
set -uo pipefail

[ $# -ge 1 ] || { sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }
WP_PATH=$1
URL=${2:-}
URL=${URL%/}
WP=(wp --path="$WP_PATH")
FAILED=0
pass() { echo "  ok   $*"; }
fail() { echo "  FAIL $*" >&2; FAILED=1; }
php_in_wp() { "${WP[@]}" eval "use SentinelShield\\Plugin; use SentinelShield\\Firewall\\EarlyGate; use SentinelShield\\Firewall\\CloudflareSync; use SentinelShield\\Firewall\\FeedSnapshot; use SentinelShield\\Support\\Mutex; \$c = Plugin::instance()->container(); $1"; }
# Kills the PHP process at a checkpoint, then runs the PHP code.
killed_at() { KILL_AT=$1 "${WP[@]}" eval "add_action( 'sentinel_shield_checkpoint', static function ( \$step ) { if ( getenv( 'KILL_AT' ) === \$step ) { posix_kill( getmypid(), SIGKILL ); } } ); \$c = SentinelShield\\Plugin::instance()->container(); $2" >/dev/null 2>&1; echo $?; }
code() { curl -s -o /dev/null -w '%{http_code}' -H "X-Forwarded-For: $1" "$URL/"; }
# "early" when the early firewall itself refused the request (before WordPress).
early() { curl -s -D - -o /dev/null -H "X-Forwarded-For: $1" "$URL/" | grep -qi '^X-Sentinel-Shield-Gate: early' && echo early || echo no; }

# A complete policy is in place: gate.json parses and both files it names are whole.
policy_intact() {
	php_in_wp '$j = json_decode( (string) @file_get_contents( EarlyGate::path() ), true ); echo is_array( $j ) && null !== FeedSnapshot::read_set( (string) $j["block_file"] ) && null !== FeedSnapshot::read_set( (string) $j["allow_file"] ) ? "intact" : "broken";'
}

echo "Crash test"
"${WP[@]}" sentinel test-mode off >/dev/null
"${WP[@]}" sentinel settings-set proxy.mode custom >/dev/null
"${WP[@]}" sentinel settings-set proxy.header X-Forwarded-For >/dev/null
"${WP[@]}" sentinel settings-set proxy.trusted_cidrs 127.0.0.1 >/dev/null
[ -n "$URL" ] || "${WP[@]}" sentinel settings-set firewall.early_gate mu_plugin >/dev/null
"${WP[@]}" sentinel settings-set firewall.server_files 1 >/dev/null
"${WP[@]}" sentinel block 203.0.113.0/24 --reason=fault-test >/dev/null
"${WP[@]}" sentinel early-gate rebuild >/dev/null

echo "Policy publication"
N=1
for STEP in gate:ranges_written gate:manifest_replaced gate:before_state; do
	IP="198.51.100.$((60 + N))"; N=$((N + 1))
	STATUS=$(killed_at "$STEP" "\$c->get( SentinelShield\\Repository\\BlockRepository::class )->add( 'block', SentinelShield\\Net\\Cidr::parse( '$IP' ), 'fault', 'manual' ); \$c->get( SentinelShield\\Firewall\\RuleCache::class )->flush(); \$c->get( SentinelShield\\Firewall\\EarlyGate::class )->rebuild();")
	[ "$STATUS" = 137 ] || fail "$STEP: the worker was not killed (exit $STATUS)"
	[ "$(policy_intact)" = intact ] && pass "killed at $STEP: the published policy is complete" || fail "killed at $STEP: the policy on disk is broken"
	if [ -n "$URL" ]; then
		[ "$(early 203.0.113.9)" = early ] && [ "$(code 198.51.100.200)" = 200 ] && pass "killed at $STEP: the early firewall still blocks and admits correctly" || fail "killed at $STEP: wrong answers over HTTP"
	fi
	PENDING=$(php_in_wp 'echo $c->get( EarlyGate::class )->publication()["pending"] ? "pending" : "done";')
	[ "$PENDING" = pending ] && pass "killed at $STEP: the change is still marked unpublished" || fail "killed at $STEP: the change is marked as published"
	# What the background job does: the pending change is built (now, or after the debounce).
	php_in_wp '$g = $c->get( EarlyGate::class ); $g->rebuild_if_dirty(); $n = wp_next_scheduled( EarlyGate::EXPIRY_HOOK ); if ( $g->publication()["pending"] && $n && $n <= time() + EarlyGate::DEBOUNCE ) { do_action( EarlyGate::EXPIRY_HOOK ); }' >/dev/null
	OK=$(php_in_wp '$s = get_site_option( EarlyGate::STATE ); echo $s["generation"] === $s["published"] && FeedSnapshot::read_set( $s["files"]["block"] )->contains( inet_pton( "'"$IP"'" ) ) && ! $c->get( EarlyGate::class )->publication()["pending"] ? "yes" : "no";')
	[ "$OK" = yes ] && pass "killed at $STEP: the next build publishes the change" || fail "killed at $STEP: not recovered by the next build"
	if [ -n "$URL" ]; then
		[ "$(early "$IP")" = early ] && pass "killed at $STEP: and the early firewall enforces it" || fail "killed at $STEP: $IP not blocked by the early firewall after recovery"
	fi
done

echo "Locks"
STATUS=$(KILL_AT=x "${WP[@]}" eval 'SentinelShield\Support\Mutex::acquire( "fault_test", 0 ) && posix_kill( getmypid(), SIGKILL );' >/dev/null 2>&1; echo $?)
[ "$STATUS" = 137 ] || fail "the lock holder was not killed (exit $STATUS)"
GOT=$(php_in_wp '$t = microtime( true ); echo Mutex::acquire( "fault_test", 3 ) ? sprintf( "%.1f", microtime( true ) - $t ) : "no";')
[ "$GOT" != no ] && pass "a lock held by a killed worker is free again (taken after ${GOT}s)" || fail "the lock of a killed worker is stranded"

echo "Cloudflare upload"
# A fake Cloudflare that applies uploads at once and remembers the list in an option.
FAKE='add_filter( "pre_http_request", static function ( $pre, $args, $url ) { if ( ! str_contains( $url, "api.cloudflare.com" ) ) { return $pre; } if ( "PUT" === $args["method"] ) { update_option( "ss_fault_cf_list", array_column( json_decode( $args["body"], true ), "ip" ) ); } return array( "headers" => array(), "response" => array( "code" => 200, "message" => "" ), "cookies" => array(), "filename" => null, "body" => wp_json_encode( array( "success" => true, "result" => array( "kind" => "ip" ) ) ) ); }, 10, 3 );'
"${WP[@]}" sentinel settings-set cloudflare.account_id aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa >/dev/null
"${WP[@]}" sentinel settings-set cloudflare.list_id bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb >/dev/null
php_in_wp '$c->get( CloudflareSync::class )->set_token( "fault-token" ); delete_site_option( CloudflareSync::STATE ); delete_option( "ss_fault_cf_list" );' >/dev/null
"${WP[@]}" sentinel settings-set cloudflare.sync 1 >/dev/null 2>&1 || true
STATUS=$(killed_at cloudflare:sent "$FAKE \$c->get( SentinelShield\\Firewall\\CloudflareSync::class )->sync( true );")
[ "$STATUS" = 137 ] || fail "the Cloudflare worker was not killed (exit $STATUS)"
STATE=$(php_in_wp 'echo ( CloudflareSync::state()["status"] ?? "" ) . "|" . ( $c->get( CloudflareSync::class )->manages_items() ? "manages" : "forgot" ) . "|" . count( (array) get_option( "ss_fault_cf_list", array() ) );')
[[ "$STATE" == unknown\|manages\|* ]] && [ "${STATE##*|}" -gt 0 ] && pass "killed after the upload: Cloudflare holds items and the state says unknown (not forgotten)" || fail "killed after the upload: state $STATE"
php_in_wp "$FAKE \$c->get( CloudflareSync::class )->sync();" >/dev/null
STATE=$(php_in_wp 'echo CloudflareSync::state()["status"] ?? "";')
[ "$STATE" = active ] && pass "the next sync confirms the list" || fail "after the next sync: $STATE"
"${WP[@]}" sentinel settings-set cloudflare.sync 0 >/dev/null 2>&1 || true
php_in_wp "$FAKE \$c->get( CloudflareSync::class )->settings_saved();" >/dev/null
LEFT=$(php_in_wp 'echo count( (array) get_option( "ss_fault_cf_list", array() ) ) . "|" . ( CloudflareSync::state()["status"] ?? "" );')
[ "$LEFT" = "0|empty" ] && pass "switching sync off empties the list" || fail "after switching sync off: $LEFT"
php_in_wp '$c->get( CloudflareSync::class )->set_token( "" ); delete_option( "ss_fault_cf_list" );' >/dev/null

echo "Full disk"
for i in $(seq 1 300); do echo "10.$((i / 250)).$((i % 250)).0/24"; done > /tmp/sentinel-shield-fault-ranges.txt
php_in_wp '$r = $c->get( SentinelShield\Repository\BlockRepository::class ); foreach ( file( "/tmp/sentinel-shield-fault-ranges.txt", FILE_IGNORE_NEW_LINES ) as $l ) { $r->add( "block", SentinelShield\Net\Cidr::parse( $l ), "fault", "manual" ); }' >/dev/null
rm -f /tmp/sentinel-shield-fault-ranges.txt
BEFORE=$(php_in_wp 'echo get_site_option( EarlyGate::STATE )["published"];')
# Files may not grow past 1 KB in this process (writes fail as on a full disk).
ERR=$( (ulimit -f 2; "${WP[@]}" eval 'pcntl_signal( SIGXFSZ, SIG_IGN ); $s = SentinelShield\Plugin::instance()->container()->get( SentinelShield\Firewall\EarlyGate::class )->rebuild(); echo $s["published"] . "|" . $s["error"];' 2>/dev/null) )
[ "${ERR%%|*}" = "$BEFORE" ] && [ -n "${ERR#*|}" ] && pass "a full disk: nothing partial is published and the error is reported" || fail "full disk: $ERR (published before: $BEFORE)"
[ "$(policy_intact)" = intact ] && pass "a full disk: the previous policy stays complete" || fail "full disk: the policy on disk is broken"
php_in_wp '$c->get( EarlyGate::class )->rebuild();' >/dev/null
OK=$(php_in_wp '$s = get_site_option( EarlyGate::STATE ); echo $s["generation"] === $s["published"] && "" === $s["error"] ? "yes" : "no";')
[ "$OK" = yes ] && pass "with room again, the next build publishes" || fail "not recovered after the disk was freed"
php_in_wp 'global $wpdb; $r = $c->get( SentinelShield\Repository\BlockRepository::class ); $wpdb->query( $wpdb->prepare( "DELETE FROM %i WHERE reason = %s", $r->table(), "fault" ) );' >/dev/null

"${WP[@]}" sentinel unblock 203.0.113.9 --include-ranges >/dev/null
"${WP[@]}" sentinel flush-cache >/dev/null
"${WP[@]}" sentinel early-gate rebuild >/dev/null
[ "$FAILED" = 0 ] && echo "Crash test passed." || { echo "Crash test FAILED."; exit 1; }
