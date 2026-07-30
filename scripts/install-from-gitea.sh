#!/bin/sh

set -eu

version=${SOKOL_PLUGIN_VERSION:-}
release_base_url=${SOKOL_PLUGIN_RELEASE_BASE_URL:-https://git.ksoft.tech/ksoft/sokol-traefik-plugin/releases/download}
destination=${SOKOL_PLUGIN_DESTINATION:-/plugins-local/src/git.ksoft.tech/ksoft/sokol-traefik-plugin}
allow_replace=${SOKOL_PLUGIN_ALLOW_REPLACE:-0}

if ! printf '%s\n' "$version" |
    grep -Eq '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'; then
    echo "SOKOL_PLUGIN_VERSION must be a stable Semantic Version such as v0.1.0" >&2
    exit 2
fi

case "$destination" in
    /*)
        ;;
    *)
        echo "SOKOL_PLUGIN_DESTINATION must be an absolute path" >&2
        exit 2
        ;;
esac

if [ -d "$destination" ] &&
    [ -n "$(find "$destination" -mindepth 1 -maxdepth 1 -print -quit)" ]; then
    if [ -f "$destination/.sokol-plugin-version" ] &&
        [ "$(cat "$destination/.sokol-plugin-version")" = "$version" ]; then
        echo "Sokol Traefik plugin $version is already installed at $destination"
        exit 0
    fi
    if [ "$allow_replace" != "1" ]; then
        echo "refusing to replace populated plugin destination: $destination" >&2
        echo "set SOKOL_PLUGIN_ALLOW_REPLACE=1 for a deliberate upgrade" >&2
        exit 1
    fi
fi

parent=${destination%/*}
mkdir -p "$parent"
workspace=$(mktemp -d "$parent/.sokol-plugin-install.XXXXXX")
cleanup() {
    rm -rf -- "$workspace"
}
trap cleanup EXIT HUP INT TERM

archive="sokol-traefik-plugin-${version}.tar.gz"
checksum="${archive}.sha256"
archive_url="${release_base_url%/}/${version}/${archive}"
checksum_url="${release_base_url%/}/${version}/${checksum}"

download() {
    url=$1
    output=$2
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$url" -o "$output"
        return
    fi
    if command -v wget >/dev/null 2>&1; then
        wget -q -O "$output" "$url"
        return
    fi
    echo "curl or wget is required to install the plugin" >&2
    exit 1
}

download "$archive_url" "$workspace/$archive"
download "$checksum_url" "$workspace/$checksum"

archive_size=$(wc -c <"$workspace/$archive")
checksum_size=$(wc -c <"$workspace/$checksum")
if [ "$archive_size" -gt 16777216 ] || [ "$checksum_size" -gt 256 ]; then
    echo "release artifact exceeds the installer size limit" >&2
    exit 1
fi

checksum_line=$(cat "$workspace/$checksum")
expected_checksum=${checksum_line%%  *}
checksum_filename=${checksum_line#*  }
if ! printf '%s\n' "$expected_checksum" |
    grep -Eq '^[0-9a-f]{64}$' ||
    [ "$checksum_filename" != "$archive" ]; then
    echo "release checksum has an invalid format" >&2
    exit 1
fi
actual_checksum=$(sha256sum "$workspace/$archive")
actual_checksum=${actual_checksum%% *}
if [ "$actual_checksum" != "$expected_checksum" ]; then
    echo "release archive checksum verification failed" >&2
    exit 1
fi
echo "$archive: OK"

if tar -tzf "$workspace/$archive" |
    grep -Eq '(^|/)\.\.(/|$)|^/'; then
    echo "release archive contains an unsafe path" >&2
    exit 1
fi

mkdir "$workspace/content"
tar -xzf "$workspace/$archive" -C "$workspace/content"
test -f "$workspace/content/.traefik.yml"
test -f "$workspace/content/go.mod"
test -f "$workspace/content/plugin.go"
test "$(cat "$workspace/content/.sokol-plugin-version")" = "$version"

if [ -d "$destination" ] &&
    [ -n "$(find "$destination" -mindepth 1 -maxdepth 1 -print -quit)" ]; then
    mv "$destination" "$workspace/previous"
    if ! mv "$workspace/content" "$destination"; then
        mv "$workspace/previous" "$destination"
        exit 1
    fi
elif [ -d "$destination" ]; then
    rmdir "$destination"
    mv "$workspace/content" "$destination"
else
    mv "$workspace/content" "$destination"
fi

echo "installed Sokol Traefik plugin $version at $destination"
