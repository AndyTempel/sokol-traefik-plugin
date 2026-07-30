#!/bin/sh

set -eu

script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository=$(CDPATH= cd -- "$script_directory/../.." && pwd)
workspace=$(mktemp -d)
cleanup() {
    rm -rf -- "$workspace"
}
trap cleanup EXIT HUP INT TERM

test "$("$repository/scripts/next-version.sh" "")" = "v0.1.0"
test "$("$repository/scripts/next-version.sh" "v0.1.0")" = "v0.1.1"
test "$("$repository/scripts/next-version.sh" "v1.9.99")" = "v1.9.100"

if "$repository/scripts/next-version.sh" "1.2.3" >/dev/null 2>&1; then
    echo "next-version accepted a tag without the required v prefix" >&2
    exit 1
fi
if "$repository/scripts/next-version.sh" "v01.2.3" >/dev/null 2>&1; then
    echo "next-version accepted a non-canonical Semantic Version" >&2
    exit 1
fi

"$repository/scripts/package-release.sh" "v1.2.3" "$workspace/first" >/dev/null
"$repository/scripts/package-release.sh" "v1.2.3" "$workspace/second" >/dev/null

archive="sokol-traefik-plugin-v1.2.3.tar.gz"
checksum="${archive}.sha256"
cmp "$workspace/first/$archive" "$workspace/second/$archive"
(
    cd "$workspace/first"
    sha256sum -c "$checksum"
)

tar -tzf "$workspace/first/$archive" >"$workspace/files"
for required in \
    ./.traefik.yml \
    ./.sokol-plugin-version \
    ./go.mod \
    ./plugin.go \
    ./pages/block.html \
    ./pages/challenge.html; do
    grep -Fx "$required" "$workspace/files" >/dev/null
done

if grep -Eq '(_test\.go|^\./tests/|^\./testdata/|^\./scripts/|^\./\.gitea/)' \
    "$workspace/files"; then
    echo "release archive contains development-only files" >&2
    exit 1
fi

mkdir -p "$workspace/releases/v1.2.3"
cp \
    "$workspace/first/$archive" \
    "$workspace/first/$checksum" \
    "$workspace/releases/v1.2.3/"

SOKOL_PLUGIN_VERSION=v1.2.3 \
SOKOL_PLUGIN_RELEASE_BASE_URL="file://$workspace/releases" \
SOKOL_PLUGIN_DESTINATION="$workspace/installed" \
    "$repository/scripts/install-from-gitea.sh"
test "$(cat "$workspace/installed/.sokol-plugin-version")" = "v1.2.3"

SOKOL_PLUGIN_VERSION=v1.2.3 \
SOKOL_PLUGIN_RELEASE_BASE_URL="file://$workspace/releases" \
SOKOL_PLUGIN_DESTINATION="$workspace/installed" \
    "$repository/scripts/install-from-gitea.sh"

if SOKOL_PLUGIN_VERSION=v1.2.4 \
    SOKOL_PLUGIN_RELEASE_BASE_URL="file://$workspace/releases" \
    SOKOL_PLUGIN_DESTINATION="$workspace/installed" \
    "$repository/scripts/install-from-gitea.sh" >/dev/null 2>&1; then
    echo "installer replaced a populated destination without authorization" >&2
    exit 1
fi

"$repository/scripts/package-release.sh" "v1.2.4" "$workspace/upgrade" >/dev/null
mkdir -p "$workspace/releases/v1.2.4"
cp "$workspace/upgrade/"* "$workspace/releases/v1.2.4/"
SOKOL_PLUGIN_VERSION=v1.2.4 \
SOKOL_PLUGIN_RELEASE_BASE_URL="file://$workspace/releases" \
SOKOL_PLUGIN_DESTINATION="$workspace/installed" \
SOKOL_PLUGIN_ALLOW_REPLACE=1 \
    "$repository/scripts/install-from-gitea.sh"
test "$(cat "$workspace/installed/.sokol-plugin-version")" = "v1.2.4"

echo "release tooling tests passed"
