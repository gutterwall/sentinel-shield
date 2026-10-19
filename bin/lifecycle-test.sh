#!/usr/bin/env bash
# Installation, upgrade, deactivation and uninstall matrix on a real site:
#
#   fresh install     activates, creates its tables and jobs, site loads
#   deactivation      no jobs left, no early firewall, server files kept as
#                     loadable empty includes, every setting and rule kept
#   reactivation      settings, rules and two-factor intact; jobs back
#   uninstall (keep)  "delete data" off: the data survives for a reinstall
#   uninstall (all)   "delete data" on: no table, option, user meta,
#                     transient, job or file of the plugin is left, and
#                     nothing that belongs to anyone else is touched
#   upgrades          from each older release zip given: site keeps loading,
#                     settings, rules and two-factor carry over, migrations run
#
# Usage: bin/lifecycle-test.sh <wordpress-path> <site-url> <new.zip> [old.zip ...]
#
# DESTRUCTIVE: installs and deletes the sentinel-shield plugin folder and its
# data. Use a throwaway site only. The plugin folder must not be a symlink (an
# uninstall deletes the folder it points to). Needs wp-cli, curl and unzip.
set -uo pipefail

[ $# -ge 3 ] || { sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }
WP_PATH=$1
URL=${2%/}
NEW=$3
shift 3
OLD=("$@")
WP=(wp --path="$WP_PATH")
PLUGINS="$WP_PATH/wp-content/plugins"
FAILED=0
pass() { echo "  ok   $*"; }
fail() { echo "  FAIL $*" >&2; FAILED=1; }
q() { "${WP[@]}" db query "$1" --skip-column-names 2>/dev/null; }
php_in_wp() { "${WP[@]}" eval "$1" 2>/dev/null; }
site_ok() { [ "$(curl -s -o /dev/null -w '%{http_code}' "$URL/")" = 200 ] && [ "$(curl -s -o /dev/null -w '%{http_code}' "$URL/wp-login.php")" = 200 ]; }
jobs() { "${WP[@]}" cron event list --fields=hook --format=csv 2>/dev/null | grep -c '^sentinel_shield' || true; }
prefix=$("${WP[@]}" db prefix 2>/dev/null)
tables() { q "SHOW TABLES LIKE '${prefix//_/\\_}sentinel%'" | grep -c sentinel; }
options() { q "SELECT COUNT(*) FROM ${prefix}options WHERE option_name LIKE '%sentinel%shield%' OR option_name LIKE '%sentinel\\_%'"; }
usermeta() { q "SELECT COUNT(*) FROM ${prefix}usermeta WHERE meta_key LIKE '%sentinel%'"; }
DATA=''

if [ -L "$PLUGINS/sentinel-shield" ]; then
	echo "Refusing: $PLUGINS/sentinel-shield is a symlink; an uninstall would delete what it points to." >&2
	exit 2
fi

install_zip() {
	"${WP[@]}" plugin deactivate sentinel-shield >/dev/null 2>&1 || true
	rm -rf "${PLUGINS:?}/sentinel-shield"
	unzip -q "$1" -d "$PLUGINS"
}

# Data another plugin owns, which nothing here may touch.
"${WP[@]}" option update other_plugin_canary keep-me >/dev/null
"${WP[@]}" user meta update 1 other_plugin_canary keep-me >/dev/null
q "CREATE TABLE IF NOT EXISTS ${prefix}other_plugin_canary (id int)" >/dev/null
canaries() { [ "$("${WP[@]}" option get other_plugin_canary 2>/dev/null)" = keep-me ] && [ "$("${WP[@]}" user meta get 1 other_plugin_canary 2>/dev/null)" = keep-me ] && [ "$(q "SHOW TABLES LIKE '${prefix}other_plugin_canary'" | grep -c other_plugin_canary)" = 1 ]; }

configure() {
	"${WP[@]}" sentinel test-mode off >/dev/null
	"${WP[@]}" sentinel settings-set firewall.early_gate mu_plugin >/dev/null
	"${WP[@]}" sentinel settings-set firewall.server_files 1 >/dev/null
	"${WP[@]}" sentinel block 203.0.113.0/24 --reason=lifecycle >/dev/null
	"${WP[@]}" user delete lc_user --yes >/dev/null 2>&1 || true
	"${WP[@]}" user create lc_user lc@example.org --role=subscriber --user_pass=Lifecycle-pass-1 >/dev/null 2>&1
	php_in_wp '$u = SentinelShield\Plugin::instance()->container()->get( SentinelShield\TwoFactor\UserTwoFactor::class ); $id = get_user_by( "login", "lc_user" )->ID; $u->new_backup_codes( $id );' >/dev/null
	"${WP[@]}" sentinel early-gate rebuild >/dev/null
	DATA=$(php_in_wp 'echo SentinelShield\Support\DataDir::path();')
}

state_kept() { # what must survive deactivation, reactivation, upgrades and a keep-data uninstall
	[ "$("${WP[@]}" sentinel settings-get firewall.server_files 2>/dev/null)" = true ] \
		&& "${WP[@]}" sentinel list --format=csv 2>/dev/null | grep -q '203.0.113.0/24' \
		&& [ "$(php_in_wp 'echo SentinelShield\Plugin::instance()->container()->get( SentinelShield\TwoFactor\UserTwoFactor::class )->backup_remaining( get_user_by( "login", "lc_user" )->ID );')" = 10 ]
}

echo "Lifecycle test: $(basename "$NEW")"
echo "Fresh install"
"${WP[@]}" plugin uninstall sentinel-shield --deactivate >/dev/null 2>&1 || true
install_zip "$NEW"
"${WP[@]}" plugin activate sentinel-shield >/dev/null && site_ok && pass "activates; the site and the login page load" || fail "activation or the site failed"
[ "$(tables)" -ge 6 ] && pass "its tables exist ($(tables))" || fail "tables missing ($(tables))"
[ "$(jobs)" -ge 1 ] && pass "its scheduled jobs exist ($(jobs))" || fail "no scheduled jobs"
configure
[ -f "$DATA/gate.json" ] && grep -q 'deny 203.0.113.0/24' "$DATA/nginx-deny.conf" && [ -f "$WP_PATH/wp-content/mu-plugins/sentinel-shield-early-gate.php" ] \
	&& pass "configured: early firewall loader, snapshot and server files written" || fail "configuration did not write its files"

echo "Deactivation"
"${WP[@]}" plugin deactivate sentinel-shield >/dev/null && site_ok && pass "deactivates; the site loads" || fail "deactivation broke the site"
[ "$(jobs)" = 0 ] && pass "no scheduled job left behind" || fail "$(jobs) jobs left: $("${WP[@]}" cron event list --fields=hook --format=csv | grep sentinel | tr '\n' ' ')"
[ ! -e "$WP_PATH/wp-content/mu-plugins/sentinel-shield-early-gate.php" ] && [ ! -e "$DATA/gate.json" ] && pass "the early firewall is gone (loader and snapshot)" || fail "the early firewall is still installed"
[ -f "$DATA/nginx-deny.conf" ] && ! grep -q '^deny' "$DATA/nginx-deny.conf" && [ -f "$DATA/apache-deny.conf" ] && grep -q 'Require all granted' "$DATA/apache-deny.conf" \
	&& pass "server files remain as empty includes (nginx and Apache keep loading)" || fail "server files missing or still blocking"
# The plugin's commands are gone while it is inactive: look at the database.
[ "$("${WP[@]}" option get sentinel_shield_settings --format=json 2>/dev/null | php -r '$s = json_decode( stream_get_contents( STDIN ), true ); echo empty( $s["firewall"]["server_files"] ) ? 0 : 1;')" = 1 ] \
	&& [ "$(q "SELECT COUNT(*) FROM ${prefix}sentinel_ip_rules WHERE label = '203.0.113.0/24'")" = 1 ] \
	&& [ "$(q "SELECT COUNT(*) FROM ${prefix}usermeta WHERE meta_key = '_sentinel_shield_2fa_backup'")" -ge 1 ] \
	&& pass "settings, rules and two-factor are kept" || fail "deactivation lost data"
canaries && pass "other plugins' data untouched" || fail "other plugins' data was changed"

echo "Reactivation"
"${WP[@]}" plugin activate sentinel-shield >/dev/null && site_ok && state_kept && pass "reactivates with everything intact" || fail "reactivation lost data"
[ "$(jobs)" -ge 1 ] && pass "scheduled jobs are back" || fail "no scheduled jobs after reactivation"
"${WP[@]}" sentinel early-gate rebuild >/dev/null
[ -f "$DATA/gate.json" ] && grep -q 'deny 203.0.113.0/24' "$DATA/nginx-deny.conf" && pass "the next build restores the snapshot and server files" || fail "snapshot not restored"

echo "Uninstall, keeping data"
"${WP[@]}" sentinel settings-set general.delete_data_on_uninstall 0 >/dev/null
"${WP[@]}" plugin uninstall sentinel-shield --deactivate >/dev/null 2>&1 && [ ! -d "$PLUGINS/sentinel-shield" ] && site_ok && pass "uninstalls; the site loads" || fail "uninstall failed"
[ "$(jobs)" = 0 ] && pass "no scheduled job left behind" || fail "$(jobs) jobs left"
[ "$(tables)" -ge 6 ] && [ "$(options)" -gt 0 ] && pass "the data is kept for a reinstall" || fail "data was deleted although 'delete data' was off"
install_zip "$NEW"
"${WP[@]}" plugin activate sentinel-shield >/dev/null && state_kept && pass "a reinstall finds everything as it was" || fail "a reinstall lost data"

echo "Uninstall, deleting data"
"${WP[@]}" sentinel settings-set general.delete_data_on_uninstall 1 >/dev/null
"${WP[@]}" sentinel early-gate rebuild >/dev/null
"${WP[@]}" plugin uninstall sentinel-shield --deactivate >/dev/null 2>&1 && site_ok && pass "uninstalls; the site loads" || fail "uninstall failed"
[ "$(tables)" = 0 ] && pass "no table left" || fail "tables left: $(q "SHOW TABLES LIKE '%sentinel%'" | tr '\n' ' ')"
[ "$(options)" = 0 ] && pass "no option or transient left" || fail "options left: $(q "SELECT option_name FROM ${prefix}options WHERE option_name LIKE '%sentinel%'" | tr '\n' ' ')"
[ "$(usermeta)" = 0 ] && pass "no user meta left" || fail "user meta left: $(q "SELECT DISTINCT meta_key FROM ${prefix}usermeta WHERE meta_key LIKE '%sentinel%'" | tr '\n' ' ')"
[ "$(jobs)" = 0 ] && pass "no scheduled job left" || fail "$(jobs) jobs left"
LEFT=$(ls -A "$DATA" 2>/dev/null | tr '\n' ' ')
[ -z "$LEFT" ] && [ ! -e "$WP_PATH/wp-content/mu-plugins/sentinel-shield-early-gate.php" ] && pass "no file left in the private folder or mu-plugins" || fail "files left: $LEFT"
canaries && pass "other plugins' data untouched" || fail "other plugins' data was changed"
"${WP[@]}" user delete lc_user --yes >/dev/null 2>&1 || true

for ZIP in "${OLD[@]}"; do
	VERSION=$(basename "$ZIP" .zip | sed 's/^sentinel-shield-//')
	echo "Upgrade from $VERSION"
	install_zip "$ZIP"
	"${WP[@]}" plugin activate sentinel-shield >/dev/null || { fail "$VERSION does not activate"; continue; }
	configure
	install_zip "$NEW" # As a plugin update does: the folder is replaced while the plugin stays active.
	"${WP[@]}" plugin activate sentinel-shield >/dev/null 2>&1 || true
	site_ok && pass "$VERSION -> new: the site loads right after the update" || fail "$VERSION -> new: the site broke"
	DBV=$(php_in_wp 'echo get_site_option( "sentinel_shield_db_version" ) . "|" . SentinelShield\Install\Schema::VERSION;')
	[ "${DBV%%|*}" = "${DBV##*|}" ] && pass "$VERSION -> new: database migrations ran (schema ${DBV##*|})" || fail "$VERSION -> new: schema ${DBV%%|*}, expected ${DBV##*|}"
	state_kept && pass "$VERSION -> new: settings, rules and two-factor carried over" || fail "$VERSION -> new: data lost"
	"${WP[@]}" sentinel early-gate rebuild >/dev/null
	OK=$(php_in_wp '$s = get_site_option( SentinelShield\Firewall\EarlyGate::STATE ); echo $s["generation"] === $s["published"] && "" === $s["error"] ? "yes" : $s["error"];')
	[ "$OK" = yes ] && pass "$VERSION -> new: the policy publishes" || fail "$VERSION -> new: publication failed: $OK"
	"${WP[@]}" sentinel settings-set general.delete_data_on_uninstall 1 >/dev/null
	"${WP[@]}" plugin uninstall sentinel-shield --deactivate >/dev/null 2>&1
	"${WP[@]}" user delete lc_user --yes >/dev/null 2>&1 || true
done

# Leave the new version installed and active.
install_zip "$NEW"
"${WP[@]}" plugin activate sentinel-shield >/dev/null
"${WP[@]}" option delete other_plugin_canary >/dev/null
"${WP[@]}" user meta delete 1 other_plugin_canary >/dev/null
q "DROP TABLE IF EXISTS ${prefix}other_plugin_canary" >/dev/null
[ "$FAILED" = 0 ] && echo "Lifecycle test passed." || { echo "Lifecycle test FAILED."; exit 1; }
