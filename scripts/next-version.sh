#!/bin/sh

set -eu

if [ "$#" -gt 1 ]; then
    echo "usage: $0 [current-version]" >&2
    exit 2
fi

if [ "$#" -eq 1 ]; then
    current=$1
else
    current=$(
        git tag --list 'v[0-9]*.[0-9]*.[0-9]*' --sort=-version:refname |
            while IFS= read -r candidate; do
                if printf '%s\n' "$candidate" |
                    grep -Eq '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'; then
                    printf '%s\n' "$candidate"
                    break
                fi
            done
    )
fi

if [ -z "$current" ]; then
    printf '%s\n' "v0.1.0"
    exit 0
fi

if ! printf '%s\n' "$current" |
    grep -Eq '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'; then
    echo "invalid stable Semantic Version: $current" >&2
    exit 2
fi

version=${current#v}
major=${version%%.*}
remainder=${version#*.}
minor=${remainder%%.*}
patch=${remainder#*.}

printf 'v%s.%s.%s\n' "$major" "$minor" "$((patch + 1))"
