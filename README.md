# BEACON

Business Ethical Automated Cyber Oversight Network.

BEACON is an ownership-verified security assessment platform for authorized web targets. It coordinates scanner execution, normalizes and correlates detections, tracks finding lifecycle, and generates HTML/PDF reports.

> Early source release: a fresh-host end-to-end installation check and Nuclei template bootstrap are still pending. See the installation status and release readiness notes below.

## Features

- DNS TXT or verification-file proof of target control.
- Quick, Standard, and Deep profiles; explicit consent for active testing.
- Nmap, ProjectDiscovery HTTPX, Katana, SSLyze, Nuclei, ZAP, and profile-dependent Nikto.
- Immutable assessment plans and approved Nuclei template snapshots.
- Organization workspaces with Admin, Analyst, and Viewer roles.
- Evidence, correlated findings, remediation workflow, retest support, and reports.

## Architecture

React is served by Nginx, which proxies requests to FastAPI. PostgreSQL stores application state. Redis and Celery dispatch control, scanner, and report work. Scanner evidence and reports use separate volumes. ZAP runs as a separate service.

## Installation status

The source includes Dockerfiles and Docker Compose configuration, but a fresh installation still needs operator configuration and acceptance testing. Do not assume the original deployment's database, secrets, or template approvals are available.

On a separate development host with Docker Compose, Git, and Python 3:

1. Run `python3 scripts/init-local-env.py` to create local secrets in an ignored `.env` file. It refuses to overwrite an existing file.
2. Configure an SMTP server you control so registration, verification, invitations, and password reset can deliver email. Never commit SMTP credentials.
3. Review `.env` and `compose.yaml`, then build with `docker compose build`.
4. Start dependencies with `docker compose up -d postgres redis` and migrate with `docker compose run --rm backend alembic upgrade head`.
5. Start services with `docker compose up -d` and check `http://localhost:5173/health`.
6. Complete the Nuclei template approval/bootstrap work described in [release readiness](docs/public-release-readiness.md) before expecting assessments to launch.

These steps describe the required setup sequence; this publication candidate has not passed a fresh-host end-to-end install. The Compose file uses fixed volume/network names and host ports: do not start a second copy alongside an existing BEACON deployment on the same Docker host.

For production, follow [the production runbook](docs/production-runbook.md) and [release checklist](docs/release-checklist.md). Configure HTTPS, secure browser sessions, trusted proxies, SMTP, and Turnstile where required. Development settings are not a production configuration.

## Development checks

```bash
cd frontend
BEACON_COMPOSE_PATH=../compose.yaml node --test tests/*.test.mjs
```

Backend tests are in `backend/tests`. Run them in an isolated environment with the runtime dependencies and pytest installed. Do not point tests at a production database. Live lab tests are opt-in and require an authorized local lab.

## Limitations

See [release readiness](docs/public-release-readiness.md) for known execution, health-reporting, and telemetry limitations. Automated assessments do not establish that a target is free of vulnerabilities. Quick still sends traffic even though ZAP active scanning is disabled.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md). Use synthetic or explicitly authorized sanitized fixtures. Do not submit credentials, production reports, user records, or third-party target data.

## Team

Created by **Aktham Alarabi**, **Sundus Al-Abdallat**, and **Salsabeel Alshayeb**.

## License and attribution

BEACON source is licensed under the [MIT License](LICENSE), with copyright credited to Aktham Alarabi, Sundus Al-Abdallat, and Salsabeel Alshayeb. Third-party scanners and dependencies retain their own licenses; review redistribution requirements before publishing container images. See [THIRD_PARTY.md](THIRD_PARTY.md).
