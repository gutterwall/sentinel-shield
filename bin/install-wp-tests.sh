#!/usr/bin/env bash
# Installs WordPress and the WordPress PHPUnit test library for the integration tests.
#
# Usage: bin/install-wp-tests.sh <db-name> <db-user> <db-pass> [db-host] [wp-version] [dir]
#   wp-version  x.y.z, or "latest" (default)
#   dir         where to install (default: /tmp/wordpress-tests); WordPress goes to
#               <dir>/wordpress and the test library to <dir>/tests-lib
#
# Then: WP_TESTS_DIR=<dir>/tests-lib vendor/bin/phpunit --testsuite integration
# (add WP_MULTISITE=1 to run the same tests on a multisite network).
#
# The database is created if missing and is emptied by every test run: never point
# this at a database you care about.
set -euo pipefail

[ $# -ge 3 ] || { sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }
DB_NAME=$1
DB_USER=$2
DB_PASS=$3
DB_HOST=${4:-localhost}
WP_VERSION=${5:-latest}
DIR=${6:-/tmp/wordpress-tests}

fail() { echo "install-wp-tests: $*" >&2; exit 1; }
command -v curl >/dev/null || fail "curl is required"

if [ "$WP_VERSION" = latest ]; then
	# The first offer is the current release (later ones are older security branches).
	WP_VERSION=$(curl -fsSL https://api.wordpress.org/core/version-check/1.7/ | grep -o '"current":"[^"]*"' | head -1 | cut -d'"' -f4)
	[ -n "$WP_VERSION" ] || fail "could not look up the latest WordPress version"
fi
[[ "$WP_VERSION" =~ ^[0-9]+\.[0-9]+(\.[0-9]+)?$ ]] || fail "unsupported version '$WP_VERSION' (use x.y.z or latest)"
echo "install-wp-tests: WordPress $WP_VERSION into $DIR"

mkdir -p "$DIR"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# WordPress itself.
if [ ! -f "$DIR/wordpress/wp-includes/version.php" ] || ! grep -q "wp_version = '$WP_VERSION'" "$DIR/wordpress/wp-includes/version.php"; then
	rm -rf "$DIR/wordpress"
	curl -fsSL "https://wordpress.org/wordpress-$WP_VERSION.tar.gz" -o "$TMP/wp.tar.gz"
	tar -xzf "$TMP/wp.tar.gz" -C "$DIR"
fi

# The test library from the matching wordpress-develop tag (tests/phpunit).
if [ ! -f "$DIR/tests-lib/.version" ] || [ "$(cat "$DIR/tests-lib/.version")" != "$WP_VERSION" ]; then
	rm -rf "$DIR/tests-lib"
	curl -fsSL "https://github.com/WordPress/wordpress-develop/archive/refs/tags/$WP_VERSION.tar.gz" -o "$TMP/dev.tar.gz"
	tar -xzf "$TMP/dev.tar.gz" -C "$TMP" --wildcards '*/tests/phpunit/includes/*' '*/tests/phpunit/data/*' '*/wp-tests-config-sample.php'
	SRC=$(find "$TMP" -maxdepth 1 -type d -name 'wordpress-develop-*' | head -1)
	[ -n "$SRC" ] || fail "unexpected wordpress-develop archive layout"
	mkdir -p "$DIR/tests-lib"
	cp -R "$SRC/tests/phpunit/includes" "$SRC/tests/phpunit/data" "$DIR/tests-lib/"
	cp "$SRC/wp-tests-config-sample.php" "$DIR/tests-lib/wp-tests-config-sample.php"
	echo "$WP_VERSION" > "$DIR/tests-lib/.version"
fi

# wp-tests-config.php
sed -e "s:dirname( __FILE__ ) . '/src/':'$DIR/wordpress/':" \
	-e "s:__DIR__ . '/src/':'$DIR/wordpress/':" \
	-e "s/youremptytestdbnamehere/$DB_NAME/" \
	-e "s/yourusernamehere/$DB_USER/" \
	-e "s/yourpasswordhere/$DB_PASS/" \
	-e "s|localhost|$DB_HOST|" \
	"$DIR/tests-lib/wp-tests-config-sample.php" > "$DIR/tests-lib/wp-tests-config.php"
grep -q "'$DIR/wordpress/'" "$DIR/tests-lib/wp-tests-config.php" || fail "could not set ABSPATH in wp-tests-config.php"

# The database.
if command -v mysqladmin >/dev/null; then
	HOST=${DB_HOST%%:*}
	PORT_ARGS=()
	if [[ "$DB_HOST" == *:* ]]; then
		PORT_ARGS=(--port="${DB_HOST##*:}" --protocol=tcp)
	fi
	mysqladmin create "$DB_NAME" --user="$DB_USER" --password="$DB_PASS" --host="$HOST" "${PORT_ARGS[@]}" 2>/dev/null \
		&& echo "install-wp-tests: created database $DB_NAME" \
		|| echo "install-wp-tests: database $DB_NAME exists (or could not be created; create it yourself)"
fi
echo "install-wp-tests: done. WP_TESTS_DIR=$DIR/tests-lib"
