# BEACON v1.0.0 Release Checklist

Completed for BEACON v1.0.0 on 2026-09-10. Every applicable gate below was reviewed before the final tag; supporting evidence is recorded in the linked release record.

Current release evidence: [`release-evidence-v1.0.0-2026-09-10.md`](release-evidence-v1.0.0-2026-09-10.md).

## Source and release identity

- [x] The intended release commit is reviewed, pushed, and the working tree is clean.
- [x] `backend/app/VERSION` contains the intended release version.
- [x] Frontend package metadata matches `backend/app/VERSION`.
- [x] `./scripts/build-release.sh` succeeds from the clean release commit.
- [x] Running backend, frontend, control-worker, and scanner-worker OCI labels match the exact version and Git revision.

## Automated quality gates

- [x] Backend tests relevant to authentication, organizations, assessments, findings, reports, scanner orchestration, and release operations pass.
- [x] Full frontend Node test suite passes with no failures.
- [x] Frontend lint passes with zero warnings/errors.
- [x] Frontend production build succeeds.
- [x] `./scripts/audit-dependencies.sh` passes for the frontend lockfile and built Python images.
- [x] Python runtime/build lockfiles are committed, hash-enforced, and match the intended dependency policy.
- [x] Docker/Compose images, Debian snapshot inputs, and downloaded scanner artifacts remain pinned to reviewed digests/checksums.
- [x] `docker compose config --quiet` succeeds.
- [x] `git diff --check` succeeds.

## Security and production configuration

- [x] Production mode disables API docs/OpenAPI exposure.
- [x] Session cookies remain `Secure`, `HttpOnly`, and host-only in production.
- [x] CSRF, trusted proxy, allowed-origin, SMTP, Turnstile, and production secrets are configured without placeholders.
- [x] Public HTTPS responses retain HSTS, CSP, nosniff, referrer, and permissions-policy protections.
- [x] Registration policy matches the intended launch posture.
- [x] No `.env`, database dump, raw scanner evidence, session token, or generated report is staged in Git.

## Database and recovery

- [x] `./scripts/backup-postgres.sh` creates a non-empty verified custom-format dump before migrations.
- [x] `./scripts/verify-backup-restore.sh <dump>` restores that exact dump successfully into the disposable PostgreSQL target.
- [x] The restored Alembic revision and table count are recorded.
- [x] `alembic heads` reports one expected head.
- [x] Production `alembic current` matches that head after deployment.
- [x] No v1.0.0 migration is introduced; the existing migration head remains `f6b1c2d3e4a5`, so no new destructive migration rollback plan is required.

## Runtime and acceptance

- [x] Required Compose services are running and expected healthchecks are healthy.
- [x] Local and public `/health` return `{"status":"ok"}`.
- [x] `BEACON_RELEASE_PUBLIC_URL=<url> ./scripts/verify-release.sh` passes from the clean release commit.
- [x] Sign-in/sign-out and session behavior passed operator browser acceptance; reset-mail delivery passed live, while password token consumption/change and CSRF semantics passed the authentication suite without automating production credentials.
- [x] Multi-organization selection persists across refresh and organization boundaries remain isolated.
- [x] Admin/analyst/viewer permissions and invitation/member-removal behavior pass live acceptance.
- [x] Dashboard, targets, assessments, findings, reports, and settings load without console-blocking errors.
- [x] A permitted assessment completes against an authorized lab target and exposes expected telemetry/findings/report behavior.

## Final v1 tag gate

- [x] Open release-blocking defects are zero, or explicitly waived with rationale.
- [x] Production backup/recovery evidence is current for the release.
- [x] Deployment and rollback operators have the production runbook available.
- [x] Release notes describe user-visible changes, migrations, operational changes, and known limitations.
- [x] Only after all applicable checks pass, change the canonical version to `1.0.0`, rebuild from the final clean commit, rerun this checklist, and create the signed/annotated v1.0.0 tag according to the repository release policy.
