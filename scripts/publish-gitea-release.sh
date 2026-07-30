#!/bin/sh

set -eu

: "${GITEA_RELEASE_SERVER_URL:?GITEA_RELEASE_SERVER_URL is required}"
: "${GITEA_RELEASE_REPOSITORY:?GITEA_RELEASE_REPOSITORY is required}"
: "${GITEA_RELEASE_SHA:?GITEA_RELEASE_SHA is required}"
: "${GITEA_RELEASE_TOKEN:?GITEA_RELEASE_TOKEN is required}"

script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository=$(CDPATH= cd -- "$script_directory/.." && pwd)
api="${GITEA_RELEASE_SERVER_URL%/}/api/v1/repos/${GITEA_RELEASE_REPOSITORY}/releases"
response=$(mktemp)
payload=$(mktemp)
cleanup() {
    rm -f -- "$response" "$payload"
}
trap cleanup EXIT HUP INT TERM

cd "$repository"

attempt=1
while [ "$attempt" -le 10 ]; do
    git fetch --force --tags origin
    version=$("$script_directory/next-version.sh")
    rm -rf -- "$repository/dist"
    "$script_directory/package-release.sh" "$version" "$repository/dist"

    python3 - "$version" "$GITEA_RELEASE_SHA" >"$payload" <<'PY'
import json
import sys

version, commit = sys.argv[1:]
json.dump(
    {
        "tag_name": version,
        "target_commitish": commit,
        "tag_message": f"Sokol Traefik plugin {version}",
        "name": version,
        "body": (
            f"Automated release of Sokol Traefik plugin {version}.\n\n"
            f"Source commit: `{commit}`\n\n"
            "Verify the runtime archive with the attached SHA-256 checksum "
            "before installing it."
        ),
        "draft": False,
        "prerelease": False,
    },
    sys.stdout,
)
PY

    status=$(
        curl \
            --silent \
            --show-error \
            --output "$response" \
            --write-out '%{http_code}' \
            --request POST \
            --header "Authorization: token $GITEA_RELEASE_TOKEN" \
            --header "Content-Type: application/json" \
            --data-binary "@$payload" \
            "$api"
    )

    if [ "$status" = "201" ]; then
        break
    fi
    if [ "$status" != "409" ]; then
        echo "Gitea release creation failed with HTTP $status" >&2
        sed -n '1,20p' "$response" >&2
        exit 1
    fi

    attempt=$((attempt + 1))
done

if [ "$attempt" -gt 10 ]; then
    echo "could not allocate a release version after 10 attempts" >&2
    exit 1
fi

release_id=$(
    python3 -c \
        'import json, sys; print(json.load(sys.stdin)["id"])' \
        <"$response"
)
archive="sokol-traefik-plugin-${version}.tar.gz"
checksum="${archive}.sha256"

for asset in "$archive" "$checksum"; do
    curl \
        --fail-with-body \
        --silent \
        --show-error \
        --request POST \
        --header "Authorization: token $GITEA_RELEASE_TOKEN" \
        --form "attachment=@$repository/dist/$asset" \
        "$api/$release_id/assets?name=$asset" >/dev/null
done

echo "published Sokol Traefik plugin $version from $GITEA_RELEASE_SHA"
