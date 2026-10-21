import os
import re
from pathlib import Path

from app.config import Settings


def _repo_root() -> Path:
    value = os.environ.get(
        "BEACON_REPO_ROOT"
    )

    if value:
        return Path(value)

    # When running outside the repository-mounted Task 19 harness,
    # repo-level deployment artifacts may not exist in the backend
    # runtime image.
    import pytest

    pytest.skip(
        "Repository deployment files "
        "are not mounted."
    )


def _read_repo_file(
    relative_path: str,
) -> str:
    path = (
        _repo_root()
        / relative_path
    )

    assert path.is_file(), path

    return path.read_text(
        encoding="utf-8"
    )


def _service_block(
    compose_text: str,
    service_name: str,
) -> str:
    lines = compose_text.splitlines()

    header = (
        f"  {service_name}:"
    )

    try:
        start = lines.index(
            header
        )
    except ValueError:
        return ""

    end = len(
        lines
    )

    service_pattern = re.compile(
        r"^  [A-Za-z0-9_.-]+:\s*$"
    )

    top_level_pattern = re.compile(
        r"^[A-Za-z0-9_.-]+:\s*$"
    )

    for index in range(
        start + 1,
        len(lines),
    ):
        line = lines[index]

        if service_pattern.match(
            line
        ):
            end = index
            break

        if top_level_pattern.match(
            line
        ):
            end = index
            break

    return "\n".join(
        lines[
            start:end
        ]
    )


def test_settings_define_scanner_runtime_budgets():
    fields = Settings.model_fields

    expected_defaults = {
        "control_worker_concurrency":
            1,
        "scanner_worker_concurrency":
            1,
        "scanner_heartbeat_interval_seconds":
            15,
        "scanner_stale_after_seconds":
            90,
        "scanner_artifact_max_bytes":
            52_428_800,
        "scanner_process_grace_seconds":
            5,
    }

    for name, expected in (
        expected_defaults.items()
    ):
        assert name in fields

        assert (
            fields[name].default
            == expected
        )


def test_compose_splits_control_and_scanner_workers():
    compose = _read_repo_file(
        "compose.yaml"
    )

    control = _service_block(
        compose,
        "control-worker",
    )

    scanner = _service_block(
        compose,
        "scanner-worker",
    )

    assert control
    assert scanner

    assert (
        _service_block(
            compose,
            "worker",
        )
        == ""
    )

    assert (
        "--queues=celery"
        in control
    )

    assert (
        "CONTROL_WORKER_CONCURRENCY"
        in control
    )

    assert (
        "--queues=scanner"
        in scanner
    )

    assert (
        "SCANNER_WORKER_CONCURRENCY"
        in scanner
    )


def test_compose_applies_resource_and_security_bounds():
    compose = _read_repo_file(
        "compose.yaml"
    )

    for service_name in (
        "control-worker",
        "scanner-worker",
        "zap",
    ):
        block = _service_block(
            compose,
            service_name,
        )

        assert block

        assert "cpus:" in block
        assert "mem_limit:" in block
        assert "pids_limit:" in block

        assert (
            "no-new-privileges:true"
            in block
        )

        assert (
            "cap_drop:"
            in block
        )

        assert re.search(
            r"(?m)^\s+- ALL\s*$",
            block,
        )

        assert (
            "cap_add:"
            not in block
        )

    lowered = compose.lower()

    assert (
        "privileged: true"
        not in lowered
    )

    assert (
        "/var/run/docker.sock"
        not in lowered
    )

    assert (
        "network_mode: host"
        not in lowered
    )

    assert (
        re.search(
            r"(?m)^\s*-\s*/:/",
            compose,
        )
        is None
    )


def test_env_example_documents_runtime_policy():
    env_example = _read_repo_file(
        ".env.example"
    )

    required = (
        "CONTROL_WORKER_CONCURRENCY=",
        "SCANNER_WORKER_CONCURRENCY=",
        "SCANNER_HEARTBEAT_INTERVAL_SECONDS=",
        "SCANNER_STALE_AFTER_SECONDS=",
        "SCANNER_ARTIFACT_MAX_BYTES=",
        "SCANNER_PROCESS_GRACE_SECONDS=",
        "CONTROL_WORKER_CPU_LIMIT=",
        "CONTROL_WORKER_MEMORY_LIMIT=",
        "CONTROL_WORKER_PIDS_LIMIT=",
        "SCANNER_WORKER_CPU_LIMIT=",
        "SCANNER_WORKER_MEMORY_LIMIT=",
        "SCANNER_WORKER_PIDS_LIMIT=",
        "ZAP_CPU_LIMIT=",
        "ZAP_MEMORY_LIMIT=",
        "ZAP_PIDS_LIMIT=",
    )

    for value in required:
        assert value in env_example


def test_worker_image_uses_graceful_sigterm():
    dockerfile = _read_repo_file(
        "backend/Dockerfile.worker"
    )

    assert re.search(
        r"(?mi)^STOPSIGNAL\s+SIGTERM\s*$",
        dockerfile,
    )
