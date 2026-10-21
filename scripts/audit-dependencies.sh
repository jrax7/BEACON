#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

printf 'Auditing frontend lockfile...\n'
docker run --rm \
  -v "$ROOT_DIR/frontend/package.json:/audit/package.json:ro" \
  -v "$ROOT_DIR/frontend/package-lock.json:/audit/package-lock.json:ro" \
  -w /audit node:22-alpine@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32 \
  npm audit --package-lock-only --audit-level=high

for image in beacon-backend beacon-scanner-worker; do
  printf 'Checking Python dependency consistency in %s...\n' "$image"
  docker run --rm --entrypoint python "$image" -m pip check

  printf 'Auditing Python packages in %s...\n' "$image"
  docker run --rm --user root --entrypoint sh "$image" -lc \
    'python -m pip install -q pip-audit >/dev/null && python -m pip_audit'
done

printf 'Dependency audits passed.\n'
