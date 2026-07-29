#!/bin/sh
set -eu

SCRIPT_DIRECTORY=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_NAME=${SOKOL_HARNESS_PROJECT:-sokol-phase4-$$}
export COMPOSE_PROJECT_NAME="$PROJECT_NAME"

cleanup() {
    STATUS=$?
    if [ "$STATUS" -ne 0 ]; then
        docker compose -f "$SCRIPT_DIRECTORY/compose.yml" logs --no-color traefik agent upstream || true
    fi
    docker compose -f "$SCRIPT_DIRECTORY/compose.yml" down --volumes --remove-orphans >/dev/null 2>&1 || true
    trap - EXIT INT TERM
    exit "$STATUS"
}
trap cleanup EXIT INT TERM

docker compose -f "$SCRIPT_DIRECTORY/compose.yml" up --build --wait --wait-timeout 60 -d traefik agent upstream
docker compose -f "$SCRIPT_DIRECTORY/compose.yml" run --rm check check

docker compose -f "$SCRIPT_DIRECTORY/compose.yml" stop agent
docker compose -f "$SCRIPT_DIRECTORY/compose.yml" run --rm check outage
docker compose -f "$SCRIPT_DIRECTORY/compose.yml" start agent
docker compose -f "$SCRIPT_DIRECTORY/compose.yml" run --rm check check
