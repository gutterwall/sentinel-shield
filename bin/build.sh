#!/usr/bin/env bash
# Builds an installable release zip from the committed source:
#   dist/sentinel-shield-<version>.zip (+ .sha256)
#
# Checks first that the version numbers agree, the readme settings reference is
# current, coding standards pass and the tests pass. The zip holds exactly the
# committed files minus those marked export-ignore in .gitattributes, plus
#   build.json        version, git commit, build time
#   checksums.sha256  SHA-256 of every file (check with: sha256sum -c checksums.sha256)
#
# Usage: bin/build.sh [--skip-tests] [--allow-dirty]
#   --skip-tests   skip phpcs and phpunit
#   --allow-dirty  build uncommitted changes to tracked files (marked -dirty in build.json)
#
# Release: bump the version (plugin header, SENTINEL_SHIELD_VERSION, readme Stable tag
# and changelog), commit, run bin/build.sh, then: git tag -a v<version> -m "Release <version>"
set -euo pipefail

SKIP_TESTS=0
ALLOW_DIRTY=0
for arg in "$@"; do
	case "$arg" in
		--skip-tests) SKIP_TESTS=1 ;;
		--allow-dirty) ALLOW_DIRTY=1 ;;
		-h|--help) sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
		*) echo "Unknown option: $arg" >&2; exit 2 ;;
	esac
done

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
SLUG=sentinel-shield
fail() { echo "build: $*" >&2; exit 1; }

# 1. Version numbers must agree.
VERSION=$(sed -n 's/^ \* Version: *//p' "$SLUG.php")
CONSTANT=$(sed -n "s/^define( 'SENTINEL_SHIELD_VERSION', '\(.*\)' );/\1/p" "$SLUG.php")
STABLE=$(sed -n 's/^Stable tag: *//p' readme.txt)
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "plugin header version '$VERSION' is not x.y.z"
[ "$CONSTANT" = "$VERSION" ] || fail "SENTINEL_SHIELD_VERSION is '$CONSTANT', plugin header says '$VERSION'"
[ "$STABLE" = "$VERSION" ] || fail "readme.txt Stable tag is '$STABLE', plugin header says '$VERSION'"
grep -qx "= $VERSION =" readme.txt || fail "readme.txt changelog has no '= $VERSION =' entry"

# 2. Source state.
git rev-parse --git-dir >/dev/null 2>&1 || fail "not a git repository"
DIRTY=""
if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
	[ "$ALLOW_DIRTY" = 1 ] || fail "uncommitted changes (commit them, or use --allow-dirty)"
	DIRTY="-dirty"
fi
if [ -n "$(git ls-files --others --exclude-standard)" ]; then
	echo "build: note: untracked files are not included:" >&2
	git ls-files --others --exclude-standard | sed 's/^/  /' >&2
fi
COMMIT=$(git rev-parse HEAD)
if TAGGED=$(git rev-parse -q --verify "refs/tags/v$VERSION^{commit}"); then
	[ "$TAGGED" = "$COMMIT" ] || fail "tag v$VERSION already exists on another commit; bump the version"
fi

# 3. Generated docs, coding standards, tests.
php bin/settings-docs.php --check || fail "docs/SETTINGS.md is out of date (php bin/settings-docs.php --write)"
if [ "$SKIP_TESTS" = 0 ]; then
	[ -x vendor/bin/phpunit ] || fail "run composer install first (or use --skip-tests)"
	vendor/bin/phpcs -q || fail "coding standards"
	vendor/bin/phpunit --testsuite unit || fail "unit tests"
	if [ -n "${WP_TESTS_DIR:-}" ]; then
		vendor/bin/phpunit --testsuite integration || fail "integration tests"
	else
		echo "build: WP_TESTS_DIR not set, skipping integration tests" >&2
	fi
fi

# 4. Stage the files.
TREE=HEAD
if [ -n "$DIRTY" ]; then
	TREE=$(git stash create)
fi
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
mkdir "$STAGE/$SLUG"
git archive --format=tar "$TREE" | tar -x -C "$STAGE/$SLUG"

while IFS= read -r -d '' file; do
	php -l "$file" >/dev/null || fail "syntax error in ${file#"$STAGE/"}"
done < <(find "$STAGE/$SLUG" -name '*.php' -print0)

BUILT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
FILES=$(find "$STAGE/$SLUG" -type f | wc -l)
cat > "$STAGE/$SLUG/build.json" <<JSON
{
	"name": "$SLUG",
	"version": "$VERSION",
	"commit": "$COMMIT$DIRTY",
	"built": "$BUILT",
	"files": $((FILES + 2))
}
JSON
(cd "$STAGE/$SLUG" && find . -type f ! -name checksums.sha256 -printf '%P\n' | LC_ALL=C sort | xargs -d '\n' sha256sum > checksums.sha256)

# 5. Zip.
mkdir -p dist
ZIP="dist/$SLUG-$VERSION.zip"
rm -f "$ZIP" "$ZIP.sha256"
(cd "$STAGE" && find "$SLUG" -print | LC_ALL=C sort | zip -qX -@ "$ROOT/$ZIP")
(cd dist && sha256sum "$(basename "$ZIP")" > "$(basename "$ZIP").sha256")

echo "Built $ZIP"
echo "  version $VERSION, commit ${COMMIT:0:12}$DIRTY, $((FILES + 2)) files, $(du -h "$ZIP" | cut -f1)"
echo "  sha256 $(cut -d' ' -f1 "$ZIP.sha256")"
