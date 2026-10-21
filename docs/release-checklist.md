# BEACON Release Checklist

Use this checklist for each release and record evidence for the exact commit and deployment being validated. Unchecked items are requirements, not claims of completed testing. The initial public source release has not passed fresh-install acceptance; see [release readiness](public-release-readiness.md).

## Source and release identity

- [ ] The intended release commit is reviewed, pushed, and the working tree is clean.
- [ ] `backend/app/VERSION` contains the intended release version.
- [ ] Frontend package metadata matches `backend/app/VERSION`.
- [ ] `./scripts/build-release.sh` succeeds from the clean release commit.
- [ ] Running backend, frontend, control-worker, and scanner-worker OCI labels match the exact version and Git revision.

## Automated quality gates

- [ ] Backend tests relevant to authentication, organizations, assessments, findings, reports, scanner orchestration, and release operations pass.
- [ ] Full frontend Node test suite passes with no failures.
- [ ] Frontend lint passes with zero warnings/errors.
- [ ] Frontend production build succeeds.
- [ ] `./scripts/audit-dependencies.sh` passes for the frontend lockfile and built Python images.
- [ ] Python runtime/build lockfiles are committed, hash-enforced, and match the intended dependency policy.
- [ ] Docker/Compose images, Debian snapshot inputs, and downloaded scanner artifacts remain pinned to reviewed digests/checksums.
- [ ] `docker compose config --quiet` succeeds.
- [ ] `git diff --check` succeeds.

## Security and production configuration

- [ ] Production mode disables API docs/OpenAPI exposure.
- [ ] Session cookies remain `Secure`, `HttpOnly`, and host-only in production.
- [ ] CSRF, trusted proxy, allowed-origin, SMTP, Turnstile, and production secrets are configured without placeholders.
- [ ] Public HTTPS responses retain HSTS, CSP, nosniff, referrer, and permissions-policy protections.
- [ ] Registration policy matches the intended launch posture.
- [ ] No `.env`, database dump, raw scanner evidence, session token, or generated report is staged in Git.

## Database and recovery

- [ ] `./scripts/backup-postgres.sh` creates a non-empty verified custom-format dump before migrations.
- [ ] `./scripts/verify-backup-restore.sh <dump>` restores that exact dump successfully into the disposable PostgreSQL target.
- [ ] The restored Alembic revision and table count are recorded.
- [ ] `alembic heads` reports one expected head.
- [ ] Production `alembic current` matches that head after deployment.
- [ ] Review included migrations and document a recovery plan for any schema or data changes.

## Runtime and acceptance

- [ ] Required Compose services are running and expected healthchecks are healthy.
- [ ] Local and public `/health` return `{"status":"ok"}`.
- [ ] `BEACON_RELEASE_PUBLIC_URL=<url> ./scripts/verify-release.sh` passes from the clean release commit.
- [ ] Sign-in/sign-out, password reset, email delivery, session behavior, and CSRF protection pass acceptance in an isolated test deployment.
- [ ] Multi-organization selection persists across refresh and organization boundaries remain isolated.
- [ ] Admin/analyst/viewer permissions and invitation/member-removal behavior pass live acceptance.
- [ ] Dashboard, targets, assessments, findings, reports, and settings load without console-blocking errors.
- [ ] A permitted assessment completes against an authorized lab target and exposes expected telemetry/findings/report behavior.

## Final release tag gate

- [ ] Open release-blocking defects are zero, or explicitly waived with rationale.
- [ ] Production backup/recovery evidence is current for the release.
- [ ] Deployment and rollback operators have the production runbook available.
- [ ] Release notes describe user-visible changes, migrations, operational changes, and known limitations.
- [ ] Only after all applicable checks pass, change the canonical version to the intended release version, rebuild from the final clean commit, rerun this checklist, and create the signed/annotated release tag according to the repository release policy.
