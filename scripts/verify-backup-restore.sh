#!/usr/bin/env bash
set -Eeuo pipefail

if [[ $# -ne 1 ]]; then
  printf 'Usage: %s /absolute/path/to/beacon.dump\n' "$0" >&2
  exit 64
fi

BACKUP="$(realpath "$1")"
test -f "$BACKUP"
test -s "$BACKUP"

NAME="beacon-restore-check-$$-${RANDOM}"
IMAGE="${BEACON_RESTORE_POSTGRES_IMAGE:-postgres:17-alpine@sha256:18cfe3ef5e6815560c98237d6216d1e5119702fb0f3894c8785dd58b8bbe5d73}"
cleanup() {
  docker rm -f "$NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

printf 'Validating backup archive...\n'
docker run --rm -i -v "$BACKUP:/backup/beacon.dump:ro" "$IMAGE" \
  pg_restore --list /backup/beacon.dump > /dev/null

printf 'Starting disposable PostgreSQL restore target...\n'
docker run -d --rm \
  --name "$NAME" \
  -e POSTGRES_HOST_AUTH_METHOD=trust \
  -v "$BACKUP:/backup/beacon.dump:ro" \
  "$IMAGE" > /dev/null

for _ in $(seq 1 60); do
  if docker exec "$NAME" pg_isready -U postgres -d postgres >/dev/null 2>&1; then
    break
  fi
  sleep 1
docker inspect "$NAME" >/dev/null 2>&1 || exit 1
done

docker exec "$NAME" pg_isready -U postgres -d postgres > /dev/null
printf 'Restoring into disposable database...\n'
docker exec "$NAME" pg_restore \
  --exit-on-error \
  --no-owner \
  --no-privileges \
  -U postgres \
  -d postgres \
  /backup/beacon.dump > /dev/null

REVISION="$(docker exec "$NAME" psql -U postgres -d postgres -Atc \
  'select version_num from alembic_version limit 1;')"
TABLE_COUNT="$(docker exec "$NAME" psql -U postgres -d postgres -Atc \
  "select count(*) from information_schema.tables where table_schema='public' and table_type='BASE TABLE';")"

test -n "$REVISION"
test "$TABLE_COUNT" -gt 0
printf 'Restore verified: revision=%s tables=%s\n' "$REVISION" "$TABLE_COUNT"
