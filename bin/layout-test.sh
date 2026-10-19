#!/usr/bin/env bash
# Site layouts other than the default, each built from scratch and tested over
# HTTP:
#
#   subdirectory      WordPress in /wp, the site at / ("giving WordPress its
#                     own directory"): the full smoke test
#   content-dir       wp-content moved and renamed (WP_CONTENT_DIR and
#                     WP_CONTENT_URL): the full smoke test
#   multisite-mapped  a multisite network with a subsite on its own domain:
#                     the plugin network-activated, the firewall, lockouts,
#                     two-factor and passkey origins on the mapped domain
#
# Usage: bin/layout-test.sh <layout> <wordpress-dir> <work-dir> <port> <db-name> <db-user> <db-pass> <db-host>
#   wordpress-dir  an unpacked WordPress release (copied, not changed)
#   PLUGIN         the plugin folder to test (default: this checkout, copied)
#
# DESTRUCTIVE: empties the database <db-name>. Needs wp-cli, curl, php.
set -euo pipefail

[ $# -ge 8 ] || { sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }
LAYOUT=$1
CORE=$(cd "$2" && pwd)
WORK=$3
PORT=$4
DB=(--dbname="$5" --dbuser="$6" --dbpass="$7" --dbhost="$8")
PLUGIN=${PLUGIN:-$(cd "$(dirname "$0")/.." && pwd)}
BIN=$(cd "$(dirname "$0")" && pwd)
ORIGIN=http://127.0.0.1:$PORT
SITE=$WORK/$LAYOUT
FAILED=0
pass() { echo "  ok   $*"; }
fail() { echo "  FAIL $*" >&2; FAILED=1; }
SERVER=''
cleanup() { [ -n "$SERVER" ] && kill "$SERVER" 2>/dev/null || true; }
trap cleanup EXIT

rm -rf "$SITE"
mkdir -p "$SITE"
install_plugin() { # target plugins folder
	mkdir -p "$1/sentinel-shield"
	(cd "$PLUGIN" && tar --exclude=./vendor --exclude=./node_modules --exclude=./dist --exclude=./build --exclude=./.git -cf - .) | tar -xf - -C "$1/sentinel-shield"
}
extra="define( 'WP_DEBUG', true ); define( 'WP_DEBUG_DISPLAY', true ); define( 'WP_ENVIRONMENT_TYPE', 'local' );"

case "$LAYOUT" in
	subdirectory)
		cp -r "$CORE" "$SITE/wp"
		printf '<?php\ndefine( "WP_USE_THEMES", true );\nrequire __DIR__ . "/wp/wp-blog-header.php";\n' > "$SITE/index.php"
		WP=(wp --path="$SITE/wp")
		"${WP[@]}" config create "${DB[@]}" --extra-php <<< "$extra" >/dev/null
		"${WP[@]}" db reset --yes >/dev/null 2>&1 || "${WP[@]}" db create >/dev/null
		"${WP[@]}" core install --url="$ORIGIN/wp" --title=Layout --admin_user=admin --admin_password="$(openssl rand -hex 12)" --admin_email=admin@example.org --skip-email >/dev/null
		"${WP[@]}" option update home "$ORIGIN" >/dev/null
		install_plugin "$SITE/wp/wp-content/plugins"
		;;
	content-dir)
		cp -r "$CORE" "$SITE/root"
		mv "$SITE/root/wp-content" "$SITE/root/assets"
		WP=(wp --path="$SITE/root")
		"${WP[@]}" config create "${DB[@]}" --extra-php <<< "$extra define( 'WP_CONTENT_DIR', __DIR__ . '/assets' ); define( 'WP_CONTENT_URL', '$ORIGIN/assets' );" >/dev/null
		"${WP[@]}" db reset --yes >/dev/null 2>&1 || "${WP[@]}" db create >/dev/null
		"${WP[@]}" core install --url="$ORIGIN" --title=Layout --admin_user=admin --admin_password="$(openssl rand -hex 12)" --admin_email=admin@example.org --skip-email >/dev/null
		install_plugin "$SITE/root/assets/plugins"
		;;
	multisite-mapped)
		cp -r "$CORE" "$SITE/root"
		WP=(wp --path="$SITE/root")
		"${WP[@]}" config create "${DB[@]}" --extra-php <<< "$extra" >/dev/null
		"${WP[@]}" db reset --yes >/dev/null 2>&1 || "${WP[@]}" db create >/dev/null
		"${WP[@]}" core multisite-install --url="127.0.0.1:$PORT" --title=Network --admin_user=admin --admin_password="$(openssl rand -hex 12)" --admin_email=admin@example.org --skip-email --skip-config >/dev/null
		cat >> "$SITE/root/wp-config.php" <<EOF
define( 'MULTISITE', true ); define( 'SUBDOMAIN_INSTALL', false ); define( 'DOMAIN_CURRENT_SITE', '127.0.0.1:$PORT' );
define( 'PATH_CURRENT_SITE', '/' ); define( 'SITE_ID_CURRENT_SITE', 1 ); define( 'BLOG_ID_CURRENT_SITE', 1 );
EOF
		# The wp-config lines must come before WordPress loads: move the require to the end.
		sed -i "/require_once ABSPATH . 'wp-settings.php';/d" "$SITE/root/wp-config.php"
		echo "require_once ABSPATH . 'wp-settings.php';" >> "$SITE/root/wp-config.php"
		install_plugin "$SITE/root/wp-content/plugins"
		;;
	*)
		echo "Unknown layout: $LAYOUT" >&2
		exit 2
		;;
esac

echo "Layout test: $LAYOUT"
if [ "$LAYOUT" = multisite-mapped ]; then
	"${WP[@]}" plugin activate sentinel-shield --network >/dev/null
else
	"${WP[@]}" plugin activate sentinel-shield >/dev/null
fi
DATA=$("${WP[@]}" eval 'echo SentinelShield\Support\DataDir::path();')
GATE=$("${WP[@]}" eval 'echo SentinelShield\Firewall\EarlyGate::gate_file();')
DOCROOT=$SITE/root
[ "$LAYOUT" = subdirectory ] && DOCROOT=$SITE
(cd "$DOCROOT" && SENTINEL_SHIELD_GATE_CONFIG=$DATA/gate.json PHP_CLI_SERVER_WORKERS=8 php -d "auto_prepend_file=$GATE" -S "127.0.0.1:$PORT" -t . > "$WORK/$LAYOUT-server.log" 2>&1) &
SERVER=$!
for i in $(seq 1 50); do curl -s -o /dev/null "$ORIGIN/" && break; sleep 0.2; done

if [ "$LAYOUT" != multisite-mapped ]; then
	SMOKE_EARLY_GATE=1 "$BIN/smoke-test.sh" "$SITE/$([ "$LAYOUT" = subdirectory ] && echo wp || echo root)" "$ORIGIN" --offline || FAILED=1
	DIR=$("${WP[@]}" eval 'echo wp_normalize_path( WP_CONTENT_DIR );')
	[ "$LAYOUT" != content-dir ] || [[ "$DIR" == */assets ]] && pass "the plugin found its content folder ($DIR)" || fail "wrong content folder: $DIR"
	[ "$FAILED" = 0 ] && echo "Layout $LAYOUT passed." || { echo "Layout $LAYOUT FAILED."; exit 1; }
	exit 0
fi

# Multisite with a subsite on its own domain.
MAPPED=mapped.test
"${WP[@]}" site create --slug=shop --title=Shop >/dev/null
SHOP=$("${WP[@]}" db query "SELECT blog_id FROM wp_blogs WHERE path = '/shop/'" --skip-column-names)
"${WP[@]}" db query "UPDATE wp_blogs SET domain = '$MAPPED:$PORT', path = '/' WHERE blog_id = $SHOP" >/dev/null
for opt in home siteurl; do "${WP[@]}" --url="$MAPPED:$PORT" option update "$opt" "http://$MAPPED:$PORT" >/dev/null; done
W=("${WP[@]}" --url="$MAPPED:$PORT")
C=(curl -s --resolve "$MAPPED:$PORT:127.0.0.1")
for set in "general.test_mode false" "proxy.mode custom" "proxy.header X-Forwarded-For" "proxy.trusted_cidrs 127.0.0.1" "firewall.early_gate prepend"; do "${W[@]}" sentinel settings-set $set >/dev/null; done
"${W[@]}" sentinel early-gate rebuild >/dev/null
code() { "${C[@]}" -o /dev/null -w '%{http_code}' -H "X-Forwarded-For: $1" "$2"; }
[ "$(code 198.51.100.10 "http://$MAPPED:$PORT/")" = 200 ] && pass "the subsite loads on its own domain" || fail "the mapped domain does not load"
[ "$("${W[@]}" eval 'echo get_current_blog_id();')" = "$SHOP" ] && pass "WordPress maps $MAPPED to the subsite" || fail "domain mapping not in effect"
RP=$("${W[@]}" eval 'echo SentinelShield\TwoFactor\WebAuthn::for_site()->rp_id();')
[ "$RP" = "$MAPPED" ] && pass "passkeys on the subsite belong to its own domain ($RP)" || fail "passkey relying party is $RP"
"${WP[@]}" user create shopper shopper@example.org --role=subscriber --user_pass=Shop-pass-123 >/dev/null 2>&1
"${W[@]}" user set-role shopper subscriber >/dev/null
for i in 1 2 3 4 5; do "${C[@]}" -o /dev/null -H 'X-Forwarded-For: 198.51.100.66' -b 'wordpress_test_cookie=WP%20Cookie%20check' --data "log=shopper&pwd=wrong$i&testcookie=1" "http://$MAPPED:$PORT/wp-login.php"; done
[ "$(code 198.51.100.66 "http://$MAPPED:$PORT/")" = 403 ] && pass "failed logins on the mapped domain lock the IP out there" || fail "no lockout on the mapped domain"
[ "$(code 198.51.100.66 "$ORIGIN/")" = 403 ] && pass "and on the main site too (the network shares its rules)" || fail "the lockout did not reach the main site"
"${W[@]}" sentinel unblock 198.51.100.66 >/dev/null
[ "$(code 198.51.100.66 "http://$MAPPED:$PORT/")" = 200 ] && pass "unblocking clears it on every domain" || fail "still blocked after unblock"
"${WP[@]}" eval '$u = SentinelShield\Plugin::instance()->container()->get( SentinelShield\TwoFactor\UserTwoFactor::class ); $id = get_user_by( "login", "shopper" )->ID; $s = $u->pending_secret( $id ); $t = time() - 300; $u->enable_totp( $id, SentinelShield\TwoFactor\Totp::code( $s, intdiv( $t, 30 ) ), $t );' >/dev/null
HEAD=$("${C[@]}" -D - -o /dev/null -H 'X-Forwarded-For: 198.51.100.11' -b 'wordpress_test_cookie=WP%20Cookie%20check' --data 'log=shopper&pwd=Shop-pass-123&testcookie=1' "http://$MAPPED:$PORT/wp-login.php")
grep -qi "^location: http://$MAPPED:$PORT/wp-login.php?action=sentinel_shield_2fa" <<< "$HEAD" && grep -qi '^set-cookie: sentinel_shield_2fa=' <<< "$HEAD" && pass "two-factor login stays on the mapped domain" || fail "two-factor redirect: $(grep -i '^location' <<< "$HEAD")"
[ "$FAILED" = 0 ] && echo "Layout $LAYOUT passed." || { echo "Layout $LAYOUT FAILED."; exit 1; }
