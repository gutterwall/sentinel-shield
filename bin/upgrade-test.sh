#!/usr/bin/env bash
# Upgrade test: installs an old release zip on a throwaway site, lets it write
# its runtime files, replaces it with a new zip (as a plugin update does) and
# checks that the site still loads and the 0.8.0 files left in the public
# uploads folder were removed or stubbed.
#
# Usage: bin/upgrade-test.sh <wordpress-path> <site-url> <old.zip> <new.zip>
#
# DESTRUCTIVE: replaces the installed sentinel-shield plugin folder. Use a
# throwaway site only (CI creates one per run). Needs wp-cli, curl and unzip.
set -euo pipefail

[ $# -eq 4 ] || { sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }
WP_PATH=$1
URL=${2%/}
OLD=$3
NEW=$4
WP=(wp --path="$WP_PATH")
PLUGINS="$WP_PATH/wp-content/plugins"
UPLOADS="$WP_PATH/wp-content/uploads/sentinel-shield"
pass() { echo "  ok   $*"; }
fail() { echo "  FAIL $*" >&2; exit 1; }

echo "Upgrade test: $(basename "$OLD") -> $(basename "$NEW")"
"${WP[@]}" plugin deactivate sentinel-shield >/dev/null 2>&1 || true
rm -rf "${PLUGINS:?}/sentinel-shield"
unzip -q "$OLD" -d "$PLUGINS"
"${WP[@]}" plugin activate sentinel-shield >/dev/null
"${WP[@]}" sentinel settings-set firewall.early_gate mu_plugin >/dev/null
"${WP[@]}" sentinel settings-set firewall.server_files 1 >/dev/null
"${WP[@]}" sentinel block 203.0.113.99 --reason=upgrade-test >/dev/null
"${WP[@]}" sentinel early-gate rebuild >/dev/null
[ -s "$UPLOADS/gate.json" ] && grep -q '203.0.113.99' "$UPLOADS/nginx-deny.conf" && pass "the old version wrote its files to public uploads" || fail "the old version did not write its files to uploads"

# A plugin update replaces the folder while the plugin stays active.
rm -rf "${PLUGINS:?}/sentinel-shield"
unzip -q "$NEW" -d "$PLUGINS"
CODE=$(curl -s -o /dev/null -w '%{http_code}' "$URL/")
[ "$CODE" = 200 ] && pass "the site loads right after the update (HTTP $CODE)" || fail "the site broke after the update (HTTP $CODE)"
"${WP[@]}" eval 'exit( version_compare( SENTINEL_SHIELD_VERSION, "0.8.2", ">=" ) ? 0 : 1 );' && pass "the new version is running" || fail "the new version is not running"
[ ! -e "$UPLOADS/gate.json" ] && pass "the old snapshot (with allowlisted addresses) is gone from uploads" || fail "gate.json is still in uploads"
! grep -q '203.0.113.99' "$UPLOADS/nginx-deny.conf" && grep -q 'no longer updated' "$UPLOADS/nginx-deny.conf" && pass "old server files are stubs that block nothing (includes keep working)" || fail "the old nginx file was not stubbed"
FAILED=$("${WP[@]}" eval 'echo count( SentinelShield\Firewall\EarlyGate::legacy_state()["failed"] ?? array( 1 ) );')
[ "$FAILED" = 0 ] && pass "nothing failed to be removed" || fail "the cleanup reports $FAILED failures"
"${WP[@]}" sentinel early-gate rebuild >/dev/null
DATA=$(dirname "$(cd "$WP_PATH" && pwd -P)")/sentinel-shield-data
[ -s "$DATA/gate.json" ] && [ ! -e "$UPLOADS/gate.json" ] && pass "the new snapshot is written to the private folder" || fail "no snapshot in $DATA"
"${WP[@]}" sentinel unblock 203.0.113.99 >/dev/null
echo "Upgrade test passed."
