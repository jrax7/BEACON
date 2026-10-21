# BEACON Production Runbook

This runbook defines the minimum operational procedure for deploying, verifying, backing up, and recovering the BEACON production stack. Run commands from the repository root on the authorized BEACON host. Never copy `.env`, database dumps, session material, or scanner evidence into Git.

## Release gate

Before a production change, confirm the intended commit is checked out and the working tree is clean. The canonical product version is `backend/app/VERSION`; `scripts/build-release.sh` injects that version and the exact Git revision into OCI labels on all first-party images. Build the affected images and run the automated test suites appropriate to the change. Then run the read-only runtime gate:

```bash
BEACON_RELEASE_PUBLIC_URL=https://beacon.example.com ./scripts/verify-release.sh
```

The verifier requires a clean tree, valid Compose configuration, database migration parity, all required runtime services, exact OCI image version/revision provenance, local health, and—when a public URL is supplied—public health plus HSTS and CSP. It does not migrate, restart, delete, or modify production data.

## Backup before database changes

Create a PostgreSQL custom-format backup before every migration or other database-affecting release:

```bash
./scripts/backup-postgres.sh
```

The script writes to `/tmp/beacon-backups/` by default, uses restrictive permissions, validates the archive with `pg_restore --list`, and only then promotes the `.partial` file to the final dump. To choose a destination, pass an absolute or relative path as the first argument, or set `BEACON_BACKUP_DIR`.

A backup is not considered recovery-ready until a restore test succeeds:

```bash
./scripts/verify-backup-restore.sh /tmp/beacon-backups/beacon-YYYYMMDDTHHMMSSZ.dump
```

The restore verifier launches a disposable PostgreSQL 17 container with no published host port, restores the archive using `--no-owner --no-privileges`, checks the Alembic revision and restored table count, then destroys the container. It never restores into the production PostgreSQL service.

## Normal deployment sequence

For a release that contains a database migration, use this order:

```bash
./scripts/backup-postgres.sh
# Verify the printed dump path with verify-backup-restore.sh before continuing.
./scripts/build-release.sh
docker compose run --rm backend alembic heads
docker compose run --rm backend alembic upgrade head
docker compose up -d --force-recreate backend control-worker scanner-worker frontend
BEACON_RELEASE_PUBLIC_URL=https://beacon.example.com ./scripts/verify-release.sh
```

Do not run `alembic upgrade head` until the backup and disposable restore check have succeeded. If a release has no schema change, omit the migration command but still take a backup before changes that could affect stored evidence or account state.

## Rollback and recovery

Application-only rollback is performed by checking out the last known-good commit, rebuilding the affected images, and recreating those services. Do not automatically run an Alembic downgrade: migrations may remove or reshape data, and rollback safety must be evaluated migration by migration.

If a schema/data rollback is required, stop application writers first, preserve a fresh incident-state backup, and restore the pre-release dump into a controlled recovery database before replacing production data. Validate the recovered Alembic revision and application health before reopening traffic. Database replacement is an operator-controlled incident action and is intentionally not automated by the repository scripts.

## Post-deployment verification

A successful release requires: `docker compose ps` showing the required services running, `/health` returning `{"status":"ok"}`, Alembic current matching head, the public HTTPS endpoint returning HSTS and CSP, and the relevant user workflow passing a real acceptance check. For organization/auth changes, verify sign-in, refresh, workspace isolation, and role restrictions. For scanner changes, validate only against an authorized lab target.

## Backup handling

Database dumps contain sensitive application data. Keep them outside the repository, restrict access to the BEACON operator account, and move long-lived backups to an approved encrypted backup location. `/tmp/beacon-backups` is a staging location, not a durable retention system. Record the backup path, Git commit, Alembic revision, and release result in the deployment log or change record.

## Reproducible dependency and supply-chain inputs

Release builds intentionally separate human-maintained dependency policy from resolved build inputs. `backend/requirements.txt` defines allowed Python ranges, while `backend/requirements.lock` records the exact runtime graph and hashes. `backend/build-requirements.in` pins the tooling used for the temporary SSLyze source build, and `backend/build-requirements.lock` records those build-tool hashes. Docker base images and Compose runtime images are digest-pinned; Debian packages are installed from the base image's recorded 2026-08-24 snapshot with the directly requested package versions pinned; downloaded scanner archives are versioned and SHA-256 verified.

When Python policy changes, refresh both lockfiles with:

```bash
./scripts/refresh-python-locks.sh
```

Treat lock and digest updates as reviewed source changes. Inspect the diff, rebuild from scratch when changing a base/snapshot/scanner artifact, run `./scripts/audit-dependencies.sh`, and rerun scanner/report acceptance as appropriate before merging. Do not hand-edit hashes merely to make a build pass. These controls make dependency and supply-chain inputs repeatable; they do not claim byte-for-byte identical OCI archives across different Docker/packaging implementations.

## Temporary SSLyze compatibility patch

BEACON currently uses released SSLyze 6.3.1 for TLS assessment. That release declares `cryptography>=43,<47`, while current security-fixed cryptography releases are 50.x. Upstream SSLyze PR #728 changes only that dependency ceiling to `<51`. Until an official SSLyze release contains the change, `backend/install_dependencies.py` downloads the official 6.3.1 source archive from PyPI, verifies its published SHA-256, applies that exact metadata-only change, installs it without dependency re-resolution, verifies the resulting package metadata, and runs `pip check`.

This compatibility patch must be removed when BEACON adopts an official SSLyze release that supports the security-fixed cryptography line. Any change to the SSLyze source version, source hash, or compatibility patch requires rerunning the SSLyze adapter tests, the local TLS acceptance check, `pip check`, and `pip-audit`.
