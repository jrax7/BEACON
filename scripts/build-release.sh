#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

[[ -z "$(git status --porcelain)" ]] || {
  printf 'FAIL: release images must be built from a clean working tree.\n' >&2
  exit 1
}

VERSION="$(tr -d '[:space:]' < backend/app/VERSION)"
REVISION="$(git rev-parse HEAD)"
[[ -n "$VERSION" ]] || { printf 'FAIL: empty BEACON version.\n' >&2; exit 1; }
[[ -n "$REVISION" ]] || { printf 'FAIL: missing Git revision.\n' >&2; exit 1; }

export BEACON_VERSION="$VERSION"
export BEACON_REVISION="$REVISION"

if [[ $# -gt 0 ]]; then
  SERVICES=("$@")
else
  SERVICES=(backend control-worker scanner-worker frontend)
fi

printf 'Building BEACON %s from %s\n' "$VERSION" "${REVISION:0:12}"
docker compose build "${SERVICES[@]}"
printf 'Release images built with OCI version/revision labels.\n'
