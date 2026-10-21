#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

umask 077
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
DEFAULT_DIR="${BEACON_BACKUP_DIR:-/tmp/beacon-backups}"
OUTPUT="${1:-${DEFAULT_DIR}/beacon-${TIMESTAMP}.dump}"
OUTPUT="$(realpath -m "$OUTPUT")"
TEMP_OUTPUT="${OUTPUT}.partial.$$"

mkdir -p "$(dirname "$OUTPUT")"
rm -f "$TEMP_OUTPUT"
trap 'rm -f "$TEMP_OUTPUT"' EXIT

printf 'Creating PostgreSQL backup...\n'
docker compose exec -T postgres sh -lc \
  'pg_dump --format=custom --no-password -U "$POSTGRES_USER" -d "$POSTGRES_DB"' \
  > "$TEMP_OUTPUT"

test -s "$TEMP_OUTPUT"
docker compose exec -T postgres pg_restore --list \
  < "$TEMP_OUTPUT" > /dev/null

mv "$TEMP_OUTPUT" "$OUTPUT"
trap - EXIT
chmod 600 "$OUTPUT"
printf 'Backup verified: %s\n' "$OUTPUT"
ls -lh "$OUTPUT"
