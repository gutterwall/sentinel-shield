#!/usr/bin/env bash
# Coverage of the whole test suite: unit and integration tests (single site and
# multisite) in-process, and the early firewall in the PHP servers the HTTP
# tests start, reported separately and merged; HTML and Clover reports; the
# floors in tests/coverage-baseline.json checked (bin/coverage-check.php).
#
# Usage: bin/coverage.sh [output-folder=build/coverage]
#   Needs PCOV or Xdebug (in php.ini, or name it in COVERAGE_EXTENSION, e.g.
#   /usr/lib/php/20230831/pcov.so) and the integration test setup (WP_TESTS_DIR).
#   BRANCHES=1 also measures branch coverage with Xdebug (slow; nightly):
#   unit, integration (single site and multisite) and the early firewall in
#   the HTTP tests' servers. Each measurement taken is also required: a
#   missing report, or a source file it does not cover, fails the run.
set -euo pipefail

cd "$(dirname "$0")/.."
OUT=${1:-build/coverage}
rm -rf "$OUT"
mkdir -p "$OUT/in-process" "$OUT/http"
OUT=$(cd "$OUT" && pwd)
PHP=(php)
if [ -n "${COVERAGE_EXTENSION:-}" ]; then
	case "$COVERAGE_EXTENSION" in
		*xdebug*) PHP+=(-d "zend_extension=$COVERAGE_EXTENSION" -d xdebug.mode=coverage) ;;
		*) PHP+=(-d "extension=$COVERAGE_EXTENSION" -d pcov.enabled=1 -d "pcov.directory=$PWD") ;;
	esac
	export SENTINEL_SHIELD_COVERAGE_EXTENSION=$COVERAGE_EXTENSION
fi
"${PHP[@]}" -r 'exit( extension_loaded( "pcov" ) || extension_loaded( "xdebug" ) ? 0 : 1 );' || { echo "No coverage extension (PCOV or Xdebug)." >&2; exit 2; }
# PCOV only watches src/ by default; early-gate.php and sentinel-shield.php are at the top.
"${PHP[@]}" -r 'exit( extension_loaded( "pcov" ) ? 0 : 1 );' && PHP+=(-d pcov.enabled=1 -d "pcov.directory=$PWD")
export SENTINEL_SHIELD_SUBPROCESS_COVERAGE=$OUT/http

echo "Unit tests"
"${PHP[@]}" vendor/bin/phpunit --testsuite unit --coverage-php "$OUT/in-process/unit.cov" --log-junit "$OUT/junit-unit.xml" | tail -1
echo "Integration tests (single site)"
"${PHP[@]}" vendor/bin/phpunit --testsuite integration --coverage-php "$OUT/in-process/integration.cov" --log-junit "$OUT/junit-integration.xml" | tail -1
echo "Integration tests (multisite)"
WP_MULTISITE=1 "${PHP[@]}" vendor/bin/phpunit --testsuite integration --coverage-php "$OUT/in-process/integration-ms.cov" --log-junit "$OUT/junit-integration-ms.xml" | tail -1

echo "Reports"
php vendor/bin/phpcov merge --clover "$OUT/in-process.xml" --text "$OUT/in-process.txt" "$OUT/in-process" >/dev/null
php vendor/bin/phpcov merge --clover "$OUT/http.xml" --text "$OUT/http.txt" "$OUT/http" >/dev/null
cp "$OUT"/http/*.cov "$OUT/in-process/" 2>/dev/null || true
php vendor/bin/phpcov merge --clover "$OUT/clover.xml" --html "$OUT/html" --text "$OUT/all.txt" "$OUT/in-process" >/dev/null
sed -n '/Summary/,/Lines/p' "$OUT/in-process.txt" | sed 's/^/  in-process  /'
echo "  over HTTP   early-gate.php: $(sed -n 's/.*Lines: *\([0-9.]*%.*\)/\1/p' "$OUT/http.txt" | head -1)"
sed -n '/Summary/,/Lines/p' "$OUT/all.txt" | sed 's/^/  combined    /'

if [ "${BRANCHES:-0}" = 1 ]; then
	echo "Branch coverage (Xdebug; slow)"
	XD=${XDEBUG_EXTENSION:-}
	XPHP=(php -d xdebug.mode=coverage)
	[ -n "$XD" ] && XPHP=(php -d "zend_extension=$XD" -d xdebug.mode=coverage)
	export SENTINEL_SHIELD_BRANCH_OUT=$OUT/branch.json
	unset SENTINEL_SHIELD_SUBPROCESS_COVERAGE
	# The servers the HTTP tests start load Xdebug the same way.
	[ -n "$XD" ] && export SENTINEL_SHIELD_COVERAGE_EXTENSION=$XD
	rm -f "$SENTINEL_SHIELD_BRANCH_OUT"
	"${XPHP[@]}" -d "auto_prepend_file=$PWD/tests/coverage/branch-collector.php" vendor/bin/phpunit --testsuite unit --no-coverage --exclude-group heavy | tail -1
	"${XPHP[@]}" -d "auto_prepend_file=$PWD/tests/coverage/branch-collector.php" vendor/bin/phpunit --testsuite integration --no-coverage --exclude-group heavy | tail -1
	WP_MULTISITE=1 "${XPHP[@]}" -d "auto_prepend_file=$PWD/tests/coverage/branch-collector.php" vendor/bin/phpunit --testsuite integration --no-coverage --exclude-group heavy | tail -1
	BRANCH_ARG=(--branches="$OUT/branch.json" --require=lines,branches)
else
	BRANCH_ARG=(--require=lines)
fi

echo
php bin/coverage-check.php "$OUT/clover.xml" "${BRANCH_ARG[@]}" ${COVERAGE_SUMMARY:+--summary="$COVERAGE_SUMMARY"} ${COVERAGE_UPDATE:+--update}
echo "HTML report: $OUT/html/index.html"
