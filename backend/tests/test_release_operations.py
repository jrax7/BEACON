from pathlib import Path
import os

BACKEND_ROOT = Path(__file__).resolve().parents[1]
ROOT = BACKEND_ROOT.parent
if not (ROOT / "compose.yaml").exists():
    container_repo = Path("/repo")
    if (container_repo / "compose.yaml").exists():
        ROOT = container_repo


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_release_scripts_exist_and_are_executable() -> None:
    for relative in (
        "scripts/backup-postgres.sh",
        "scripts/build-release.sh",
        "scripts/audit-dependencies.sh",
        "scripts/verify-backup-restore.sh",
        "scripts/verify-release.sh",
    ):
        path = ROOT / relative
        assert path.is_file()
        assert os.access(path, os.X_OK)


def test_database_backup_is_custom_format_and_verified() -> None:
    source = read("scripts/backup-postgres.sh")
    assert "pg_dump" in source
    assert "--format=custom" in source
    assert "pg_restore --list" in source
    assert "umask 077" in source
    assert ".partial" in source
    assert "test -s" in source


def test_restore_check_is_disposable_and_not_bound_to_host() -> None:
    source = read("scripts/verify-backup-restore.sh")
    assert "docker run -d --rm" in source
    assert "pg_restore" in source
    assert "--exit-on-error" in source
    assert "--no-owner" in source
    assert "alembic_version" in source
    assert "docker rm -f" in source
    assert "-p " not in source
    assert "--publish" not in source
    assert "docker compose exec" not in source


def test_release_verifier_is_non_destructive() -> None:
    source = read("scripts/verify-release.sh")
    for token in (
        "git status --porcelain",
        "git diff --check",
        "docker compose config --quiet",
        "alembic heads",
        "alembic current",
        "docker compose ps --services --status running",
        "127.0.0.1:5173/health",
        "BEACON_RELEASE_PUBLIC_URL",
        "strict-transport-security",
        "content-security-policy",
    ):
        assert token in source
    for destructive in (
        "docker compose down",
        "alembic upgrade",
        "alembic downgrade",
        "docker system prune",
        "git reset --hard",
    ):
        assert destructive not in source


def test_readme_links_production_runbook() -> None:
    readme = read("README.md")
    assert "docs/production-runbook.md" in readme
    assert "docs/release-checklist.md" in readme


def test_product_version_is_consistent_across_metadata() -> None:
    import json

    version = read("backend/app/VERSION").strip()
    package = json.loads(read("frontend/package.json"))
    package_lock = json.loads(read("frontend/package-lock.json"))
    assert version == "1.0.0"
    assert package["version"] == version
    assert package_lock["version"] == version
    assert package_lock["packages"][""]["version"] == version
    assert 'with_name("VERSION")' in read("backend/app/main.py")


def test_first_party_images_carry_release_provenance_labels() -> None:
    for relative in (
        "backend/Dockerfile",
        "backend/Dockerfile.worker",
        "frontend/Dockerfile",
    ):
        source = read(relative)
        assert "ARG BEACON_VERSION=development" in source
        assert "ARG BEACON_REVISION=unknown" in source
        assert "org.opencontainers.image.version" in source
        assert "org.opencontainers.image.revision" in source

    compose = read("compose.yaml")
    assert compose.count('BEACON_VERSION: "${BEACON_VERSION:-development}"') == 4
    assert compose.count('BEACON_REVISION: "${BEACON_REVISION:-unknown}"') == 4


def test_release_build_requires_clean_tree_and_injects_version_revision() -> None:
    source = read("scripts/build-release.sh")
    assert "git status --porcelain" in source
    assert "backend/app/VERSION" in source
    assert "git rev-parse HEAD" in source
    assert 'export BEACON_VERSION="$VERSION"' in source
    assert 'export BEACON_REVISION="$REVISION"' in source
    assert "docker compose build" in source


def test_release_verifier_checks_running_image_provenance() -> None:
    source = read("scripts/verify-release.sh")
    assert "org.opencontainers.image.version" in source
    assert "org.opencontainers.image.revision" in source
    assert "backend/app/VERSION" in source
    assert "git rev-parse HEAD" in source


def test_release_checklist_guards_v1_tagging() -> None:
    source = read("docs/release-checklist.md")
    assert "scripts/build-release.sh" in source
    assert "scripts/backup-postgres.sh" in source
    assert "scripts/verify-backup-restore.sh" in source
    assert "scripts/verify-release.sh" in source
    assert "Multi-organization selection persists across refresh" in source
    assert "authorized lab target" in source
    assert "change the canonical version to `1.0.0`" in source


def test_dependency_audit_checks_both_package_ecosystems() -> None:
    source = read("scripts/audit-dependencies.sh")
    assert "npm audit --package-lock-only --audit-level=high" in source
    assert "-m pip check" in source
    assert "python -m pip_audit" in source
    assert "beacon-backend" in source
    assert "beacon-scanner-worker" in source


def test_secure_scanner_dependency_install_is_pinned_and_verified() -> None:
    installer = read("backend/install_dependencies.py")
    requirements = read("backend/requirements.txt")
    assert 'SSLYZE_VERSION = "6.3.1"' in installer
    assert "files.pythonhosted.org/packages/source/s/sslyze" in installer
    assert "2cd4062f82a3fa605dbd34e3b71f99961e4e7cf438879da1c52f619855ffbc1d" in installer
    assert 'OLD_REQUIREMENT = "cryptography>=43,<47"' in installer
    assert 'PATCHED_REQUIREMENT = "cryptography>=43,<51"' in installer
    assert 'filter="data"' in installer
    assert 'pip("check")' in installer
    assert "weasyprint>=70,<71" in requirements
    assert "cryptography>=50.0.1,<51" in requirements
    assert "sslyze==6.3.1" not in requirements


def test_python_dependencies_are_hash_locked() -> None:
    runtime_lock = read("backend/requirements.lock")
    build_lock = read("backend/build-requirements.lock")
    installer = read("backend/install_dependencies.py")

    assert runtime_lock.count("--hash=sha256:") > 50
    assert "fastapi==0.141.1" in runtime_lock
    assert "cryptography==50.0.1" in runtime_lock
    assert "weasyprint==70.0" in runtime_lock
    assert "pip==26.2.1" in build_lock
    assert "setuptools==84.0.0" in build_lock
    assert "wheel==0.48.0" in build_lock
    assert '"--require-hashes"' in installer
    assert 'ROOT / "requirements.lock"' in installer
    assert '"--no-build-isolation"' in installer


def test_container_inputs_are_digest_pinned() -> None:
    dockerfiles = "\n".join(
        read(path)
        for path in (
            "backend/Dockerfile",
            "backend/Dockerfile.worker",
            "frontend/Dockerfile",
        )
    )
    for line in dockerfiles.splitlines():
        if line.startswith("FROM "):
            assert "@sha256:" in line

    compose = read("compose.yaml")
    for image in (
        "postgres:17-alpine",
        "redis:7-alpine",
        "bkimminich/juice-shop:latest",
        "nginx:alpine",
        "ghcr.io/zaproxy/zaproxy:stable",
    ):
        assert f"image: {image}@sha256:" in compose

    assert "node:22-alpine@sha256:" in read("scripts/audit-dependencies.sh")
    assert "postgres:17-alpine@sha256:" in read("scripts/verify-backup-restore.sh")


def test_os_and_scanner_supply_chain_inputs_are_frozen() -> None:
    backend = read("backend/Dockerfile")
    worker = read("backend/Dockerfile.worker")

    for source in (backend, worker):
        assert "ARG DEBIAN_SNAPSHOT=20260824T000000Z" in source
        assert "snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT}" in source
        assert 'Acquire::Check-Valid-Until "false";' in source

    for package_pin in (
        "fontconfig=2.15.0-2.3",
        "libharfbuzz-subset0=10.2.0-1+deb13u1",
        "libpango-1.0-0=1.56.3-1",
    ):
        assert package_pin in backend

    for checksum_name in (
        "HTTPX_AMD64_SHA256",
        "HTTPX_ARM64_SHA256",
        "KATANA_AMD64_SHA256",
        "KATANA_ARM64_SHA256",
        "NIKTO_SHA256",
    ):
        assert checksum_name in worker
    assert worker.count("sha256sum --check --strict") >= 5


def test_python_lock_refresh_is_pinned_and_reviewable() -> None:
    source = read("scripts/refresh-python-locks.sh")
    build_input = read("backend/build-requirements.in")
    assert "python:3.12-slim@sha256:" in source
    assert 'PIP_TOOLS_VERSION="7.5.2"' in source
    assert "--generate-hashes" in source
    assert "requirements.lock" in source
    assert "build-requirements.lock" in source
    assert "pip==26.2.1" in build_input
    assert "setuptools==84.0.0" in build_input
    assert "wheel==0.48.0" in build_input
