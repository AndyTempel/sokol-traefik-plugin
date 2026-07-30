#!/bin/sh

set -eu

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
    echo "usage: $0 VERSION [OUTPUT_DIRECTORY]" >&2
    exit 2
fi

version=$1
output_directory=${2:-dist}

if ! printf '%s\n' "$version" |
    grep -Eq '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'; then
    echo "invalid stable Semantic Version: $version" >&2
    exit 2
fi

script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository=$(CDPATH= cd -- "$script_directory/.." && pwd)
mkdir -p "$output_directory"
output_directory=$(CDPATH= cd -- "$output_directory" && pwd)

staging=$(mktemp -d)
cleanup() {
    rm -rf -- "$staging"
}
trap cleanup EXIT HUP INT TERM

for source in "$repository"/*.go; do
    case "$source" in
        *_test.go)
            continue
            ;;
    esac
    cp "$source" "$staging/"
done

cp \
    "$repository/.traefik.yml" \
    "$repository/go.mod" \
    "$repository/README.md" \
    "$repository/SBOM.cdx.json" \
    "$repository/THIRD_PARTY_NOTICES.md" \
    "$staging/"
cp -R "$repository/pages" "$staging/pages"
printf '%s\n' "$version" >"$staging/.sokol-plugin-version"
chmod 0755 "$staging" "$staging/pages"

archive="sokol-traefik-plugin-${version}.tar.gz"
checksum="${archive}.sha256"

if ! tar --version 2>/dev/null | grep -q 'GNU tar'; then
    echo "release packaging requires GNU tar" >&2
    exit 1
fi

tar \
    --sort=name \
    --mtime='UTC 1970-01-01' \
    --owner=0 \
    --group=0 \
    --numeric-owner \
    -C "$staging" \
    -cf - . |
    gzip -n >"$output_directory/$archive"

(
    cd "$output_directory"
    sha256sum "$archive" >"$checksum"
)

printf '%s\n' "$output_directory/$archive"
printf '%s\n' "$output_directory/$checksum"
