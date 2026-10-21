#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
pass() { printf 'PASS: %s\n' "$*"; }

if [[ "${BEACON_RELEASE_ALLOW_DIRTY:-0}" != "1" ]]; then
  [[ -z "$(git status --porcelain)" ]] || fail 'working tree is not clean'
fi
git diff --check
pass "git ${BEACON_RELEASE_ALLOW_DIRTY:+diff }checks"

docker compose config --quiet
pass 'docker compose configuration'

HEAD_REV="$(docker compose run --rm --no-deps backend alembic heads 2>/dev/null | awk '/\(head\)/ {print $1; exit}')"
CURRENT_REV="$(docker compose run --rm --no-deps backend alembic current 2>/dev/null | awk '/\(head\)/ {print $1; exit}')"
[[ -n "$HEAD_REV" ]] || fail 'unable to determine Alembic head'
[[ "$CURRENT_REV" == "$HEAD_REV" ]] || fail "database revision ${CURRENT_REV:-unknown} != head $HEAD_REV"
pass "database migration head $HEAD_REV"

REQUIRED=(postgres redis backend frontend control-worker scanner-worker zap)
RUNNING="$(docker compose ps --services --status running)"
for service in "${REQUIRED[@]}"; do
  grep -Fxq "$service" <<<"$RUNNING" || fail "$service is not running"
done
pass 'required services are running'

if [[ "${BEACON_RELEASE_ALLOW_DIRTY:-0}" == "1" ]]; then
  printf 'SKIP: image provenance check (dirty-tree override enabled)\n'
else
  EXPECTED_VERSION="$(tr -d '[:space:]' < backend/app/VERSION)"
  EXPECTED_REVISION="$(git rev-parse HEAD)"
  for service in backend frontend control-worker scanner-worker; do
    container_id="$(docker compose ps -q "$service")"
    [[ -n "$container_id" ]] || fail "unable to resolve $service container"
    image_version="$(docker inspect --format '{{ index .Config.Labels "org.opencontainers.image.version" }}' "$container_id")"
    image_revision="$(docker inspect --format '{{ index .Config.Labels "org.opencontainers.image.revision" }}' "$container_id")"
    [[ "$image_version" == "$EXPECTED_VERSION" ]] \
      || fail "$service image version ${image_version:-missing} != $EXPECTED_VERSION"
    [[ "$image_revision" == "$EXPECTED_REVISION" ]] \
      || fail "$service image revision ${image_revision:-missing} != $EXPECTED_REVISION"
  done
  pass "running image provenance $EXPECTED_VERSION @ ${EXPECTED_REVISION:0:12}"
fi

LOCAL_HEALTH="$(curl --fail --silent --show-error --max-time 10 http://127.0.0.1:5173/health)"
grep -Eq '"status"[[:space:]]*:[[:space:]]*"ok"' <<<"$LOCAL_HEALTH" \
  || fail 'local health endpoint is not OK'
pass 'local application health'

PUBLIC_URL="${BEACON_RELEASE_PUBLIC_URL:-}"
if [[ -n "$PUBLIC_URL" ]]; then
  PUBLIC_URL="${PUBLIC_URL%/}"
  PUBLIC_HEALTH="$(curl --fail --silent --show-error --max-time 15 "$PUBLIC_URL/health")"
  grep -Eq '"status"[[:space:]]*:[[:space:]]*"ok"' <<<"$PUBLIC_HEALTH" \
    || fail 'public health endpoint is not OK'
  HEADERS="$(curl --fail --silent --show-error --max-time 15 -D - -o /dev/null "$PUBLIC_URL/")"
  grep -Eiq '^strict-transport-security:' <<<"$HEADERS" || fail 'public HSTS header missing'
  grep -Eiq '^content-security-policy:' <<<"$HEADERS" || fail 'public CSP header missing'
  pass 'public health and browser security headers'
else
  printf 'SKIP: public check (set BEACON_RELEASE_PUBLIC_URL)\n'
fi

printf 'Release verification passed for commit %s\n' "$(git rev-parse --short HEAD)"
