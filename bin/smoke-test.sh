#!/usr/bin/env bash
# End-to-end smoke test of a real WordPress site with Sentinel Shield active:
# the plugin boots, the firewall, brute-force protection, generic login errors,
# two-factor redirect, the scans and every admin page work over HTTP.
#
# Usage: bin/smoke-test.sh <wordpress-path> <site-url> [--offline]
#   --offline  skip the WordPress.org checksum check (needs internet otherwise)
#
# The site must reach PHP directly from 127.0.0.1, with several workers for the
# concurrency check (e.g. PHP_CLI_SERVER_WORKERS=8 php -S 127.0.0.1:8099), and
# allow application passwords over HTTP (define WP_ENVIRONMENT_TYPE as local).
# DESTRUCTIVE: it changes settings, creates users and blocks test IPs. Use a
# throwaway site only (CI creates one per run). Needs wp-cli and curl.
set -euo pipefail

[ $# -ge 2 ] || { sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }
WP_PATH=$1
URL=${2%/}
OFFLINE=0
[ "${3:-}" = --offline ] && OFFLINE=1

WP=(wp --path="$WP_PATH")
JAR=$(mktemp)
OUT=$(mktemp)
trap 'rm -f "$JAR" "$OUT"' EXIT
PASSED=0
pass() { PASSED=$((PASSED + 1)); echo "  ok   $*"; }
fail() { echo "  FAIL $*" >&2; [ -s "$OUT" ] && sed 's/<[^>]*>//g' "$OUT" | grep -v '^\s*$' | head -20 >&2; exit 1; }
# Requests appear to come from the given IP: the site trusts X-Forwarded-For from 127.0.0.1.
get() { local ip=$1; shift; curl -s -o "$OUT" -w '%{http_code}' -H "X-Forwarded-For: $ip" "$@"; }
login() { # ip user pass -> HTTP code; response headers in $OUT.h
	curl -s -o "$OUT" -D "$OUT.h" -w '%{http_code}' -H "X-Forwarded-For: $1" -b 'wordpress_test_cookie=WP%20Cookie%20check' \
		--data-urlencode "log=$2" --data-urlencode "pwd=$3" -d 'wp-submit=Log+In&testcookie=1' "$URL/wp-login.php"
}
login_error() { sed -n 's/.*<div id="login_error"[^>]*>\(.*\)/\1/p' "$OUT" | sed 's/<[^>]*>//g' | head -c 200; }

echo "Sentinel Shield smoke test: $URL"

echo "Setup"
"${WP[@]}" plugin is-active sentinel-shield || fail "the plugin is not active"
"${WP[@]}" sentinel test-mode off >/dev/null
"${WP[@]}" sentinel settings-set proxy.mode custom >/dev/null
"${WP[@]}" sentinel settings-set proxy.header X-Forwarded-For >/dev/null
"${WP[@]}" sentinel settings-set proxy.trusted_cidrs 127.0.0.1 >/dev/null
"${WP[@]}" sentinel settings-set twofa.required none >/dev/null
"${WP[@]}" sentinel login-attempts --clear >/dev/null
SMOKE_PASS="Smoke-$(date +%s)-pass"
"${WP[@]}" user delete smoke_admin smoke_user --yes >/dev/null 2>&1 || true
"${WP[@]}" user create smoke_admin smoke_admin@example.org --role=administrator --user_pass="$SMOKE_PASS" >/dev/null
"${WP[@]}" user create smoke_user smoke_user@example.org --role=subscriber --user_pass="$SMOKE_PASS" >/dev/null
"${WP[@]}" sentinel status >/dev/null && pass "plugin active, wp sentinel status works"

echo "Firewall and brute force"
[ "$(get 198.51.100.10 "$URL/")" = 200 ] && pass "home page loads" || fail "home page did not load"
[ "$(get 127.0.0.1 "$URL/")" = 200 ] || fail "home page without a forwarding header"
login 198.51.100.11 nobody-here wrong >/dev/null; UNKNOWN=$(login_error)
login 198.51.100.12 smoke_user wrong >/dev/null; WRONG=$(login_error)
[ -n "$UNKNOWN" ] && [ "$UNKNOWN" = "$WRONG" ] && pass "same message for unknown user and wrong password" || fail "login errors differ: '$UNKNOWN' / '$WRONG'"
for i in 1 2 3 4 5; do login 198.51.100.66 smoke_user "wrong$i" >/dev/null; done
login 198.51.100.66 smoke_user "$SMOKE_PASS" >/dev/null
login_error | grep -q 'Too many' || [ "$(get 198.51.100.66 "$URL/")" = 403 ] || fail "6th login after 5 failures was not refused"
pass "5 failed logins: the right password is refused too"
[ "$(get 198.51.100.66 "$URL/")" = 403 ] && pass "the IP is locked out of the site" || fail "locked-out IP still reaches the site"
[ "$(get 198.51.100.67 "$URL/")" = 200 ] && pass "other IPs are unaffected" || fail "another IP was blocked"
"${WP[@]}" sentinel unblock 198.51.100.66 >/dev/null
[ "$(get 198.51.100.66 "$URL/")" = 200 ] && pass "wp sentinel unblock lifts it" || fail "unblock did not work"

echo "REST API application passwords"
APP=$("${WP[@]}" user application-password create smoke_user smoke --porcelain 2>/dev/null || true)
if [ -n "$APP" ]; then
	rest() { curl -s -o "$OUT" -w '%{http_code}' -H "X-Forwarded-For: $1" -u "smoke_user:$2" "$URL/?rest_route=/wp/v2/users/me&context=edit"; }
	[ "$(rest 198.51.100.50 "$APP")" = 200 ] && grep -q '"smoke_user"' "$OUT" && pass "a correct application password works" || fail "application password login failed"
	for i in 1 2 3 4 5; do rest 198.51.100.51 "wrong wrong wrong $i" >/dev/null; done
	CODE=$(rest 198.51.100.51 "$APP")
	[ "$CODE" = 429 ] || [ "$CODE" = 403 ] && pass "5 wrong application passwords: the right one is refused too (HTTP $CODE)" || fail "REST guesses were not limited (HTTP $CODE)"
	"${WP[@]}" sentinel unblock 198.51.100.51 >/dev/null
else
	echo "  skip application passwords are not available (set WP_ENVIRONMENT_TYPE to local)"
fi

echo "Concurrency"
"${WP[@]}" sentinel login-attempts --clear >/dev/null
seq 1 20 | xargs -P 20 -I{} curl -s -o /dev/null -H 'X-Forwarded-For: 198.51.100.77' -b 'wordpress_test_cookie=WP%20Cookie%20check' \
	--data-urlencode 'log=smoke_user' --data-urlencode 'pwd=parallel{}' -d 'wp-submit=Log+In&testcookie=1' "$URL/wp-login.php"
TRIED=$("${WP[@]}" db query "SELECT COUNT(*) FROM $("${WP[@]}" db prefix)sentinel_login_attempts WHERE ip = INET6_ATON('198.51.100.77')" --skip-column-names 2>/dev/null | tr -d '[:space:]')
[ -n "$TRIED" ] && [ "$TRIED" -le 5 ] && pass "20 simultaneous wrong logins from one IP: $TRIED checked, never more than the limit" || fail "concurrent logins got past the limit ($TRIED checked)"
"${WP[@]}" sentinel unblock 198.51.100.77 >/dev/null

if [ "${SMOKE_EARLY_GATE:-0}" = 1 ]; then
	# The server must run with auto_prepend_file=.../early-gate.php (and SENTINEL_SHIELD_GATE_CONFIG if needed).
	echo "Early firewall (auto_prepend_file)"
	"${WP[@]}" sentinel settings-set firewall.early_gate prepend >/dev/null
	"${WP[@]}" sentinel block 198.51.100.88 --reason=smoke >/dev/null
	"${WP[@]}" sentinel early-gate rebuild >/dev/null
	CODE=$(curl -s -o "$OUT" -D "$OUT.h" -w '%{http_code}' -H 'X-Forwarded-For: 198.51.100.88' "$URL/")
	[ "$CODE" = 403 ] && grep -qi '^x-sentinel-shield-gate: early' "$OUT.h" && pass "a blocked IP is refused before WordPress loads" || fail "the early firewall did not block (HTTP $CODE)"
	CODE=$(curl -s -o "$OUT" -D "$OUT.h" -w '%{http_code}' -H 'X-Forwarded-For: 198.51.100.89' "$URL/")
	[ "$CODE" = 200 ] && ! grep -qi '^x-sentinel-shield-gate' "$OUT.h" && pass "other visitors pass through to WordPress" || fail "the early firewall blocked another visitor (HTTP $CODE)"
	DATA=$(dirname "$(cd "$WP_PATH" && pwd -P)")/sentinel-shield-data
	[ -s "$DATA/gate.json" ] && [ ! -e "$WP_PATH/wp-content/uploads/sentinel-shield/gate.json" ] && pass "the snapshot is kept outside the web root ($DATA)" || fail "the snapshot is not in $DATA"
	CODE=$(curl -s -o "$OUT" -w '%{http_code}' -H 'X-Forwarded-For: 198.51.100.88' "$URL/wp-content/plugins/sentinel-shield/early-gate.php")
	[ "$CODE" = 200 ] && [ ! -s "$OUT" ] && pass "early-gate.php requested directly does nothing" || fail "early-gate.php answered a direct request (HTTP $CODE)"
	"${WP[@]}" sentinel unblock 198.51.100.88 >/dev/null
	"${WP[@]}" sentinel early-gate rebuild >/dev/null
	[ "$(get 198.51.100.88 "$URL/")" = 200 ] && pass "unblocking takes effect in the early firewall" || fail "still blocked after unblock"
	"${WP[@]}" sentinel settings-set firewall.early_gate off >/dev/null
	rm -f "$OUT.h"
fi

echo "Two-factor"
"${WP[@]}" sentinel settings-set twofa.required all >/dev/null
CODE=$(login 198.51.100.20 smoke_user "$SMOKE_PASS")
grep -qi '^location:.*action=sentinel_shield_2fa' "$OUT.h" && ! grep -qi 'set-cookie: wordpress_logged_in' "$OUT.h" \
	&& pass "correct password goes to the code screen without a login cookie" || fail "no two-factor step (HTTP $CODE)"
"${WP[@]}" sentinel settings-set twofa.email false >/dev/null
login 198.51.100.21 smoke_user "$SMOKE_PASS" >/dev/null
login_error | grep -q 'two-factor' && ! grep -qi 'set-cookie: wordpress_logged_in' "$OUT.h" \
	&& pass "required account without any method is refused" || fail "required account without a method got in"
"${WP[@]}" sentinel settings-set twofa.email true >/dev/null
"${WP[@]}" sentinel settings-set twofa.required none >/dev/null
rm -f "$OUT.h"

echo "Health"
"${WP[@]}" sentinel health --format=csv > "$OUT" 2>&1 || true
grep -q '^state,label,detail' "$OUT" && pass "wp sentinel health reports" || fail "wp sentinel health failed"

echo "Scans"
"${WP[@]}" sentinel scan > "$OUT" 2>&1 && pass "malware scan: clean" || fail "malware scan reported problems"
if [ "$OFFLINE" = 0 ]; then
	"${WP[@]}" sentinel verify > "$OUT" 2>&1 && pass "core and plugins match WordPress.org checksums" || fail "checksum verification reported problems"
fi

echo "Admin pages"
curl -s -o /dev/null -c "$JAR" -H 'X-Forwarded-For: 198.51.100.30' -b 'wordpress_test_cookie=WP%20Cookie%20check' \
	--data-urlencode 'log=smoke_admin' --data-urlencode "pwd=$SMOKE_PASS" -d 'wp-submit=Log+In&testcookie=1' "$URL/wp-login.php"
PAGES="sentinel-shield sentinel-shield-rules sentinel-shield-events sentinel-shield-lockdown sentinel-shield-cron sentinel-shield-tools"
for tab in general ip_detection lockout login geo blocklists server alerts lockdown modules docs; do PAGES="$PAGES sentinel-shield-settings&tab=$tab"; done
for page in $PAGES; do
	CODE=$(curl -s -o "$OUT" -w '%{http_code}' -b "$JAR" -H 'X-Forwarded-For: 198.51.100.30' "$URL/wp-admin/admin.php?page=$page")
	[ "$CODE" = 200 ] || fail "admin page $page: HTTP $CODE"
	grep -qE '(Fatal error|Warning|Notice|Deprecated)</b>:|Fatal error:' "$OUT" && fail "PHP error on admin page $page"
	grep -q 'id="wpbody-content"' "$OUT" || fail "admin page $page did not render (not logged in?)"
done
CODE=$(curl -s -o "$OUT" -w '%{http_code}' -b "$JAR" -H 'X-Forwarded-For: 198.51.100.30' "$URL/wp-admin/users.php?page=sentinel-shield-2fa")
[ "$CODE" = 200 ] && grep -q '<svg' "$OUT" || fail "two-factor setup page (HTTP $CODE)"
pass "all admin pages render without PHP errors"

echo "Cleanup"
"${WP[@]}" user delete smoke_admin smoke_user --yes >/dev/null
"${WP[@]}" sentinel login-attempts --clear >/dev/null
echo "Smoke test passed: $PASSED checks."
