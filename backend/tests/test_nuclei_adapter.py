import hashlib
from pathlib import Path

import pytest


def _digest(content: bytes) -> str:
    return hashlib.sha256(
        content
    ).hexdigest()


def _entry(
    *,
    template_id="template-one",
    template_path="http/template-one.yaml",
    digest=None,
):
    if digest is None:
        digest = "a" * 64

    return {
        "template_id": template_id,
        "template_revision_or_digest": digest,
        "template_source": (
            "projectdiscovery/nuclei-templates"
        ),
        "template_path": template_path,
        "template_severity": "medium",
        "template_tags": [
            "test",
        ],
        "protocol": "http",
        "policy_group": "BEACON_STANDARD",
        "approved_profiles": [
            "deep",
            "standard",
        ],
    }


def _snapshot(
    *entries,
):
    from app.models.nuclei_template_snapshot import (
        NucleiTemplateSnapshot,
    )

    return NucleiTemplateSnapshot(
        policy_version="nuclei-policy-v1",
        nuclei_version="3.11.1",
        template_source=(
            "projectdiscovery/nuclei-templates"
        ),
        template_source_revision="v10.4.7",
        snapshot_digest="f" * 64,
        approved_groups=[
            "BEACON_SAFE",
            "BEACON_STANDARD",
        ],
        template_manifest=list(
            entries
        ),
        template_count=len(
            entries
        ),
    )


def _write_template(
    root: Path,
    relative_path: str,
    content: bytes,
) -> Path:
    path = root / relative_path

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    path.write_bytes(
        content
    )

    return path


def _prepared_snapshot(
    tmp_path: Path,
):
    root = (
        tmp_path
        / "nuclei-templates-v10.4.7"
    )

    content = (
        b"id: template-one\n"
        b"info:\n"
        b"  name: Template One\n"
    )

    template = _write_template(
        root,
        "http/template-one.yaml",
        content,
    )

    snapshot = _snapshot(
        _entry(
            digest=_digest(
                content
            ),
        )
    )

    target_list = (
        tmp_path
        / "targets.txt"
    )

    target_list.write_text(
        "https://portal.example.com/\n",
        encoding="utf-8",
    )

    return (
        root,
        template,
        snapshot,
        target_list,
    )


def test_resolver_returns_only_verified_snapshot_files(
    tmp_path,
):
    from app.scanners.nuclei import (
        resolve_snapshot_template_paths,
    )

    root = (
        tmp_path
        / "snapshot"
    )

    first_content = b"id: first\n"
    second_content = b"id: second\n"

    first = _write_template(
        root,
        "http/first.yaml",
        first_content,
    )

    second = _write_template(
        root,
        "ssl/second.yaml",
        second_content,
    )

    snapshot = _snapshot(
        _entry(
            template_id="first",
            template_path="http/first.yaml",
            digest=_digest(
                first_content
            ),
        ),
        _entry(
            template_id="second",
            template_path="ssl/second.yaml",
            digest=_digest(
                second_content
            ),
        ),
    )

    resolved = (
        resolve_snapshot_template_paths(
            snapshot=snapshot,
            template_root=root,
        )
    )

    assert resolved == (
        first.resolve(),
        second.resolve(),
    )


def test_resolver_rejects_missing_snapshot_file(
    tmp_path,
):
    from app.scanners.nuclei import (
        NucleiScannerError,
        resolve_snapshot_template_paths,
    )

    root = tmp_path / "snapshot"
    root.mkdir()

    snapshot = _snapshot(
        _entry(
            template_path="http/missing.yaml",
        )
    )

    with pytest.raises(
        NucleiScannerError,
        match="missing",
    ):
        resolve_snapshot_template_paths(
            snapshot=snapshot,
            template_root=root,
        )


def test_resolver_rejects_symlink_escape(
    tmp_path,
):
    from app.scanners.nuclei import (
        NucleiScannerError,
        resolve_snapshot_template_paths,
    )

    root = tmp_path / "snapshot"
    root.mkdir()

    outside = (
        tmp_path
        / "outside.yaml"
    )

    content = b"id: outside\n"

    outside.write_bytes(
        content
    )

    link = (
        root
        / "http"
        / "escape.yaml"
    )

    link.parent.mkdir(
        parents=True,
    )

    link.symlink_to(
        outside
    )

    snapshot = _snapshot(
        _entry(
            template_path=(
                "http/escape.yaml"
            ),
            digest=_digest(
                content
            ),
        )
    )

    with pytest.raises(
        NucleiScannerError,
        match="escape",
    ):
        resolve_snapshot_template_paths(
            snapshot=snapshot,
            template_root=root,
        )


def test_resolver_rejects_template_digest_mismatch(
    tmp_path,
):
    from app.scanners.nuclei import (
        NucleiScannerError,
        resolve_snapshot_template_paths,
    )

    root = tmp_path / "snapshot"

    _write_template(
        root,
        "http/template-one.yaml",
        b"id: modified-template\n",
    )

    snapshot = _snapshot(
        _entry(
            digest="a" * 64,
        )
    )

    with pytest.raises(
        NucleiScannerError,
        match="digest",
    ):
        resolve_snapshot_template_paths(
            snapshot=snapshot,
            template_root=root,
        )


def test_command_has_governed_safety_flags(
    tmp_path,
):
    from app.scanners.nuclei import (
        build_nuclei_command,
    )

    (
        root,
        _,
        snapshot,
        target_list,
    ) = _prepared_snapshot(
        tmp_path
    )

    command = build_nuclei_command(
        snapshot=snapshot,
        template_root=root,
        target_list_path=target_list,
        allow_local_network_access=False,
        nuclei_binary=(
            "/usr/local/bin/nuclei"
        ),
    )

    assert command[0] == (
        "/usr/local/bin/nuclei"
    )

    required_flags = {
        "-jsonl",
        "-silent",
        "-no-color",
        "-omit-template",
        "-disable-update-check",
        "-no-interactsh",
        "-disable-unsigned-templates",
        "-no-stdin",
        "-no-httpx",
        "-restrict-local-network-access",
    }

    assert required_flags.issubset(
        set(command)
    )

    list_index = command.index(
        "-list"
    )

    assert command[
        list_index + 1
    ] == str(
        target_list.resolve()
    )
    # Large HTTP bodies belong in bounded evidence handling,
    # not duplicated into Nuclei JSONL stdout.
    assert "-omit-raw" in command


def test_command_selects_exact_template_files_not_directory(
    tmp_path,
):
    from app.scanners.nuclei import (
        build_nuclei_command,
    )

    (
        root,
        template,
        snapshot,
        target_list,
    ) = _prepared_snapshot(
        tmp_path
    )

    command = build_nuclei_command(
        snapshot=snapshot,
        template_root=root,
        target_list_path=target_list,
        allow_local_network_access=False,
        nuclei_binary="nuclei",
    )

    template_indexes = [
        index
        for index, value in enumerate(
            command
        )
        if value == "-templates"
    ]

    assert len(
        template_indexes
    ) == 1

    selected = [
        command[index + 1]
        for index in template_indexes
    ]

    assert selected == [
        str(
            template.resolve()
        )
    ]

    assert str(
        root.resolve()
    ) not in command


def test_command_never_enables_unsafe_or_remote_features(
    tmp_path,
):
    from app.scanners.nuclei import (
        build_nuclei_command,
    )

    (
        root,
        _,
        snapshot,
        target_list,
    ) = _prepared_snapshot(
        tmp_path
    )

    command = build_nuclei_command(
        snapshot=snapshot,
        template_root=root,
        target_list_path=target_list,
        allow_local_network_access=False,
        nuclei_binary="nuclei",
    )

    forbidden = {
        "-code",
        "-headless",
        "-dast",
        "-fuzz",
        "-automatic-scan",
        "-new-templates",
        "-update",
        "-update-templates",
        "-update-template-dir",
        "-template-url",
        "-workflow-url",
        "-allow-local-file-access",
        "-env-vars",
        "-scan-all-ips",
        "-system-resolvers",
        "-dashboard",
        "-dashboard-upload",
        "-uncover",
    }

    assert forbidden.isdisjoint(
        set(command)
    )


def test_local_network_restriction_can_only_be_explicitly_relaxed(
    tmp_path,
):
    from app.scanners.nuclei import (
        build_nuclei_command,
    )

    (
        root,
        _,
        snapshot,
        target_list,
    ) = _prepared_snapshot(
        tmp_path
    )

    restricted = build_nuclei_command(
        snapshot=snapshot,
        template_root=root,
        target_list_path=target_list,
        allow_local_network_access=False,
        nuclei_binary="nuclei",
    )

    permitted = build_nuclei_command(
        snapshot=snapshot,
        template_root=root,
        target_list_path=target_list,
        allow_local_network_access=True,
        nuclei_binary="nuclei",
    )

    assert (
        "-restrict-local-network-access"
        in restricted
    )

    assert (
        "-restrict-local-network-access"
        not in permitted
    )


def test_empty_snapshot_is_rejected_instead_of_running_default_templates(
    tmp_path,
):
    from app.scanners.nuclei import (
        NucleiScannerError,
        build_nuclei_command,
    )

    root = tmp_path / "snapshot"
    root.mkdir()

    target_list = tmp_path / "targets.txt"

    target_list.write_text(
        "https://portal.example.com/\n",
        encoding="utf-8",
    )

    snapshot = _snapshot()

    with pytest.raises(
        NucleiScannerError,
        match="empty",
    ):
        build_nuclei_command(
            snapshot=snapshot,
            template_root=root,
            target_list_path=target_list,
            allow_local_network_access=False,
            nuclei_binary="nuclei",
        )


def test_command_rejects_missing_target_list(
    tmp_path,
):
    from app.scanners.nuclei import (
        NucleiScannerError,
        build_nuclei_command,
    )

    (
        root,
        _,
        snapshot,
        _,
    ) = _prepared_snapshot(
        tmp_path
    )

    with pytest.raises(
        NucleiScannerError,
        match="target",
    ):
        build_nuclei_command(
            snapshot=snapshot,
            template_root=root,
            target_list_path=(
                tmp_path
                / "does-not-exist.txt"
            ),
            allow_local_network_access=False,
            nuclei_binary="nuclei",
        )

SAMPLE_NUCLEI_JSONL = b"""{"template":"http/cves/2026/CVE-2026-12345.yaml","template-id":"CVE-2026-12345","info":{"name":"Example Vulnerability","severity":"high","tags":["cve","example"]},"matcher-name":"vulnerable-response","type":"http","host":"https://portal.example.com","matched-at":"https://portal.example.com/vulnerable","ip":"203.0.113.10","timestamp":"2026-08-28T18:30:00Z","extracted-results":["example-value"]}
"""


def _parser_snapshot():
    return _snapshot(
        {
            "template_id": "CVE-2026-12345",
            "template_revision_or_digest": "c" * 64,
            "template_source": (
                "projectdiscovery/nuclei-templates"
            ),
            "template_path": (
                "http/cves/2026/"
                "CVE-2026-12345.yaml"
            ),
            "template_severity": "high",
            "template_tags": [
                "cve",
                "example",
            ],
            "protocol": "http",
            "policy_group": "BEACON_STANDARD",
            "approved_profiles": [
                "deep",
                "standard",
            ],
        }
    )


def test_parser_returns_structured_detection_candidate():
    from app.scanners.nuclei import (
        parse_nuclei_jsonl,
    )

    result = parse_nuclei_jsonl(
        raw_jsonl=SAMPLE_NUCLEI_JSONL,
        snapshot=_parser_snapshot(),
        max_output_bytes=1_000_000,
    )

    assert len(
        result.detection_candidates
    ) == 1

    candidate = (
        result.detection_candidates[0]
    )

    assert candidate.template_id == (
        "CVE-2026-12345"
    )

    assert candidate.template_revision_or_digest == (
        "c" * 64
    )

    assert candidate.template_source == (
        "projectdiscovery/nuclei-templates"
    )

    assert candidate.template_path == (
        "http/cves/2026/"
        "CVE-2026-12345.yaml"
    )

    assert candidate.template_name == (
        "Example Vulnerability"
    )

    assert candidate.template_severity == (
        "high"
    )

    assert candidate.template_tags == (
        "cve",
        "example",
    )

    assert candidate.protocol == "http"

    assert candidate.matcher_name == (
        "vulnerable-response"
    )

    assert candidate.extractor_name is None

    assert candidate.host == (
        "https://portal.example.com"
    )

    assert candidate.matched_at == (
        "https://portal.example.com/vulnerable"
    )

    assert candidate.ip == (
        "203.0.113.10"
    )

    assert candidate.extracted_results == (
        "example-value",
    )

    assert candidate.timestamp == (
        "2026-08-28T18:30:00Z"
    )


def test_parser_preserves_raw_jsonl():
    from app.scanners.nuclei import (
        parse_nuclei_jsonl,
    )

    result = parse_nuclei_jsonl(
        raw_jsonl=SAMPLE_NUCLEI_JSONL,
        snapshot=_parser_snapshot(),
        max_output_bytes=1_000_000,
    )

    assert result.raw_jsonl == (
        SAMPLE_NUCLEI_JSONL
    )


def test_parser_uses_snapshot_provenance_not_untrusted_output():
    from app.scanners.nuclei import (
        parse_nuclei_jsonl,
    )

    raw = b"""{"template":"attacker/path.yaml","template-id":"CVE-2026-12345","info":{"name":"Output Name","severity":"critical","tags":["attacker"]},"type":"dns","host":"https://portal.example.com","matched-at":"https://portal.example.com/"}
"""

    result = parse_nuclei_jsonl(
        raw_jsonl=raw,
        snapshot=_parser_snapshot(),
        max_output_bytes=1_000_000,
    )

    candidate = (
        result.detection_candidates[0]
    )

    assert candidate.template_path == (
        "http/cves/2026/"
        "CVE-2026-12345.yaml"
    )

    assert candidate.template_revision_or_digest == (
        "c" * 64
    )

    assert candidate.template_source == (
        "projectdiscovery/nuclei-templates"
    )

    assert candidate.template_severity == (
        "high"
    )

    assert candidate.template_tags == (
        "cve",
        "example",
    )

    assert candidate.protocol == "http"


def test_parser_rejects_template_not_in_snapshot():
    from app.scanners.nuclei import (
        NucleiScannerError,
        parse_nuclei_jsonl,
    )

    raw = b"""{"template-id":"unknown-template","info":{"name":"Unknown","severity":"high"},"type":"http","host":"https://portal.example.com","matched-at":"https://portal.example.com/"}
"""

    with pytest.raises(
        NucleiScannerError,
        match="snapshot",
    ):
        parse_nuclei_jsonl(
            raw_jsonl=raw,
            snapshot=_parser_snapshot(),
            max_output_bytes=1_000_000,
        )


def test_parser_rejects_missing_template_id():
    from app.scanners.nuclei import (
        NucleiScannerError,
        parse_nuclei_jsonl,
    )

    raw = b"""{"info":{"name":"Missing Template ID","severity":"high"},"type":"http","host":"https://portal.example.com"}
"""

    with pytest.raises(
        NucleiScannerError,
        match="template",
    ):
        parse_nuclei_jsonl(
            raw_jsonl=raw,
            snapshot=_parser_snapshot(),
            max_output_bytes=1_000_000,
        )


def test_parser_rejects_malformed_json():
    from app.scanners.nuclei import (
        NucleiScannerError,
        parse_nuclei_jsonl,
    )

    with pytest.raises(
        NucleiScannerError,
        match="JSON",
    ):
        parse_nuclei_jsonl(
            raw_jsonl=b"{not-json}\n",
            snapshot=_parser_snapshot(),
            max_output_bytes=1_000_000,
        )


def test_parser_rejects_non_object_json_event():
    from app.scanners.nuclei import (
        NucleiScannerError,
        parse_nuclei_jsonl,
    )

    with pytest.raises(
        NucleiScannerError,
        match="object",
    ):
        parse_nuclei_jsonl(
            raw_jsonl=b'["unexpected"]\n',
            snapshot=_parser_snapshot(),
            max_output_bytes=1_000_000,
        )


def test_parser_rejects_oversized_output():
    from app.scanners.nuclei import (
        NucleiScannerError,
        parse_nuclei_jsonl,
    )

    with pytest.raises(
        NucleiScannerError,
        match="output",
    ):
        parse_nuclei_jsonl(
            raw_jsonl=SAMPLE_NUCLEI_JSONL,
            snapshot=_parser_snapshot(),
            max_output_bytes=10,
        )


@pytest.mark.parametrize(
    "max_output_bytes",
    [
        0,
        -1,
    ],
)
def test_parser_rejects_non_positive_output_budget(
    max_output_bytes,
):
    from app.scanners.nuclei import (
        NucleiScannerError,
        parse_nuclei_jsonl,
    )

    with pytest.raises(
        NucleiScannerError,
        match="output",
    ):
        parse_nuclei_jsonl(
            raw_jsonl=SAMPLE_NUCLEI_JSONL,
            snapshot=_parser_snapshot(),
            max_output_bytes=max_output_bytes,
        )


def test_parser_skips_blank_lines():
    from app.scanners.nuclei import (
        parse_nuclei_jsonl,
    )

    raw = (
        b"\n"
        + SAMPLE_NUCLEI_JSONL
        + b"\n"
    )

    result = parse_nuclei_jsonl(
        raw_jsonl=raw,
        snapshot=_parser_snapshot(),
        max_output_bytes=1_000_000,
    )

    assert len(
        result.detection_candidates
    ) == 1


def test_parser_handles_extractor_only_detection():
    from app.scanners.nuclei import (
        parse_nuclei_jsonl,
    )

    raw = b"""{"template-id":"CVE-2026-12345","info":{"name":"Extractor Example","severity":"high"},"extractor-name":"version","type":"http","host":"https://portal.example.com","matched-at":"https://portal.example.com/","extracted-results":["1.2.3","1.2.4"]}
"""

    result = parse_nuclei_jsonl(
        raw_jsonl=raw,
        snapshot=_parser_snapshot(),
        max_output_bytes=1_000_000,
    )

    candidate = (
        result.detection_candidates[0]
    )

    assert candidate.matcher_name is None

    assert candidate.extractor_name == (
        "version"
    )

    assert candidate.extracted_results == (
        "1.2.3",
        "1.2.4",
    )


def test_parser_normalizes_missing_optional_fields():
    from app.scanners.nuclei import (
        parse_nuclei_jsonl,
    )

    raw = b"""{"template-id":"CVE-2026-12345","info":{"name":"Minimal"},"host":"https://portal.example.com"}
"""

    result = parse_nuclei_jsonl(
        raw_jsonl=raw,
        snapshot=_parser_snapshot(),
        max_output_bytes=1_000_000,
    )

    candidate = (
        result.detection_candidates[0]
    )

    assert candidate.matcher_name is None
    assert candidate.extractor_name is None
    assert candidate.matched_at is None
    assert candidate.ip is None
    assert candidate.timestamp is None
    assert candidate.extracted_results == ()


def test_parser_ignores_explicit_failed_matcher_status():
    from app.scanners.nuclei import (
        parse_nuclei_jsonl,
    )

    raw = b"""{"template-id":"CVE-2026-12345","matcher-status":false,"info":{"name":"Failed Match"},"type":"http","host":"https://portal.example.com"}
"""

    result = parse_nuclei_jsonl(
        raw_jsonl=raw,
        snapshot=_parser_snapshot(),
        max_output_bytes=1_000_000,
    )

    assert (
        result.detection_candidates
        == ()
    )


def test_parser_keeps_distinct_matcher_detections():
    from app.scanners.nuclei import (
        parse_nuclei_jsonl,
    )

    first = b"""{"template-id":"CVE-2026-12345","matcher-name":"matcher-a","info":{"name":"Example"},"type":"http","host":"https://portal.example.com","matched-at":"https://portal.example.com/"}
"""

    second = b"""{"template-id":"CVE-2026-12345","matcher-name":"matcher-b","info":{"name":"Example"},"type":"http","host":"https://portal.example.com","matched-at":"https://portal.example.com/"}
"""

    result = parse_nuclei_jsonl(
        raw_jsonl=(
            first
            + second
        ),
        snapshot=_parser_snapshot(),
        max_output_bytes=1_000_000,
    )

    assert [
        candidate.matcher_name
        for candidate
        in result.detection_candidates
    ] == [
        "matcher-a",
        "matcher-b",
    ]

RUNNER_NUCLEI_JSONL = b"""{"template-id":"template-one","info":{"name":"Runner Match","severity":"critical"},"matcher-name":"body","type":"http","host":"https://portal.example.com","matched-at":"https://portal.example.com/test","ip":"203.0.113.10"}
"""


def test_runner_executes_governed_command_and_parses_output(
    monkeypatch,
    tmp_path,
):
    import subprocess

    from app.scanners.nuclei import (
        run_nuclei_assessment,
    )

    (
        root,
        template,
        snapshot,
        target_list,
    ) = _prepared_snapshot(
        tmp_path
    )

    captured = {}

    def fake_run(
        command,
        **kwargs,
    ):
        captured["command"] = command
        captured["kwargs"] = kwargs

        return subprocess.CompletedProcess(
            args=command,
            returncode=0,
            stdout=RUNNER_NUCLEI_JSONL,
            stderr=b"",
        )

    monkeypatch.setattr(
        "app.scanners.nuclei.subprocess.run",
        fake_run,
    )

    result = run_nuclei_assessment(
        snapshot=snapshot,
        template_root=root,
        target_list_path=target_list,
        allow_local_network_access=False,
        nuclei_binary="nuclei",
        timeout_seconds=120,
        max_output_bytes=1_000_000,
    )

    command = captured["command"]

    assert command[0] == "nuclei"

    assert "-disable-update-check" in command
    assert "-no-interactsh" in command
    assert "-disable-unsigned-templates" in command
    assert "-no-stdin" in command
    assert "-no-httpx" in command

    template_index = command.index(
        "-templates"
    )

    assert command[
        template_index + 1
    ] == str(
        template.resolve()
    )

    assert result.raw_jsonl == (
        RUNNER_NUCLEI_JSONL
    )

    assert len(
        result.detection_candidates
    ) == 1

    candidate = (
        result.detection_candidates[0]
    )

    assert candidate.template_id == (
        "template-one"
    )

    # Snapshot provenance remains authoritative.
    assert candidate.template_severity == (
        "medium"
    )

    assert candidate.template_tags == (
        "test",
    )

    assert candidate.protocol == "http"


def test_runner_uses_noninteractive_subprocess_contract(
    monkeypatch,
    tmp_path,
):
    import subprocess

    from app.scanners.nuclei import (
        run_nuclei_assessment,
    )

    (
        root,
        _,
        snapshot,
        target_list,
    ) = _prepared_snapshot(
        tmp_path
    )

    captured = {}

    def fake_run(
        command,
        **kwargs,
    ):
        captured["kwargs"] = kwargs

        return subprocess.CompletedProcess(
            args=command,
            returncode=0,
            stdout=b"",
            stderr=b"",
        )

    monkeypatch.setattr(
        "app.scanners.nuclei.subprocess.run",
        fake_run,
    )

    run_nuclei_assessment(
        snapshot=snapshot,
        template_root=root,
        target_list_path=target_list,
        allow_local_network_access=False,
        nuclei_binary="nuclei",
        timeout_seconds=12,
        max_output_bytes=1_000_000,
    )

    kwargs = captured["kwargs"]

    assert kwargs["capture_output"] is True
    assert kwargs["check"] is False
    assert kwargs["timeout"] == 12
    assert kwargs["stdin"] is subprocess.DEVNULL

    assert kwargs["env"]["LC_ALL"] == "C"
    assert kwargs["env"]["LANG"] == "C"

    assert "shell" not in kwargs


@pytest.mark.parametrize(
    (
        "field",
        "value",
        "message",
    ),
    [
        (
            "timeout_seconds",
            0,
            "timeout",
        ),
        (
            "timeout_seconds",
            -1,
            "timeout",
        ),
        (
            "max_output_bytes",
            0,
            "output",
        ),
        (
            "max_output_bytes",
            -1,
            "output",
        ),
    ],
)
def test_runner_rejects_non_positive_budgets(
    monkeypatch,
    tmp_path,
    field,
    value,
    message,
):
    from app.scanners.nuclei import (
        NucleiScannerError,
        run_nuclei_assessment,
    )

    (
        root,
        _,
        snapshot,
        target_list,
    ) = _prepared_snapshot(
        tmp_path
    )

    def fail_if_called(
        *args,
        **kwargs,
    ):
        raise AssertionError(
            "Nuclei must not start "
            "with invalid budgets"
        )

    monkeypatch.setattr(
        "app.scanners.nuclei.subprocess.run",
        fail_if_called,
    )

    kwargs = {
        "snapshot": snapshot,
        "template_root": root,
        "target_list_path": target_list,
        "allow_local_network_access": False,
        "nuclei_binary": "nuclei",
        "timeout_seconds": 120,
        "max_output_bytes": 1_000_000,
    }

    kwargs[field] = value

    with pytest.raises(
        NucleiScannerError,
        match=message,
    ):
        run_nuclei_assessment(
            **kwargs,
        )


def test_runner_reports_missing_executable(
    monkeypatch,
    tmp_path,
):
    from app.scanners.nuclei import (
        NucleiScannerError,
        run_nuclei_assessment,
    )

    (
        root,
        _,
        snapshot,
        target_list,
    ) = _prepared_snapshot(
        tmp_path
    )

    def fake_run(
        *args,
        **kwargs,
    ):
        raise FileNotFoundError(
            "nuclei"
        )

    monkeypatch.setattr(
        "app.scanners.nuclei.subprocess.run",
        fake_run,
    )

    with pytest.raises(
        NucleiScannerError,
        match="executable",
    ):
        run_nuclei_assessment(
            snapshot=snapshot,
            template_root=root,
            target_list_path=target_list,
            allow_local_network_access=False,
            nuclei_binary="nuclei",
            timeout_seconds=120,
            max_output_bytes=1_000_000,
        )


def test_runner_reports_timeout(
    monkeypatch,
    tmp_path,
):
    import subprocess

    from app.scanners.nuclei import (
        NucleiScannerError,
        run_nuclei_assessment,
    )

    (
        root,
        _,
        snapshot,
        target_list,
    ) = _prepared_snapshot(
        tmp_path
    )

    def fake_run(
        command,
        **kwargs,
    ):
        raise subprocess.TimeoutExpired(
            cmd=command,
            timeout=kwargs["timeout"],
        )

    monkeypatch.setattr(
        "app.scanners.nuclei.subprocess.run",
        fake_run,
    )

    with pytest.raises(
        NucleiScannerError,
        match="timed out",
    ):
        run_nuclei_assessment(
            snapshot=snapshot,
            template_root=root,
            target_list_path=target_list,
            allow_local_network_access=False,
            nuclei_binary="nuclei",
            timeout_seconds=5,
            max_output_bytes=1_000_000,
        )


def test_runner_rejects_process_failure(
    monkeypatch,
    tmp_path,
):
    import subprocess

    from app.scanners.nuclei import (
        NucleiScannerError,
        run_nuclei_assessment,
    )

    (
        root,
        _,
        snapshot,
        target_list,
    ) = _prepared_snapshot(
        tmp_path
    )

    def fake_run(
        command,
        **kwargs,
    ):
        return subprocess.CompletedProcess(
            args=command,
            returncode=2,
            stdout=b"",
            stderr=b"fatal nuclei error\n",
        )

    monkeypatch.setattr(
        "app.scanners.nuclei.subprocess.run",
        fake_run,
    )

    with pytest.raises(
        NucleiScannerError,
        match="failed",
    ):
        run_nuclei_assessment(
            snapshot=snapshot,
            template_root=root,
            target_list_path=target_list,
            allow_local_network_access=False,
            nuclei_binary="nuclei",
            timeout_seconds=120,
            max_output_bytes=1_000_000,
        )


def test_runner_rejects_oversized_stdout(
    monkeypatch,
    tmp_path,
):
    import subprocess

    from app.scanners.nuclei import (
        NucleiScannerError,
        run_nuclei_assessment,
    )

    (
        root,
        _,
        snapshot,
        target_list,
    ) = _prepared_snapshot(
        tmp_path
    )

    def fake_run(
        command,
        **kwargs,
    ):
        return subprocess.CompletedProcess(
            args=command,
            returncode=0,
            stdout=b"x" * 100,
            stderr=b"",
        )

    monkeypatch.setattr(
        "app.scanners.nuclei.subprocess.run",
        fake_run,
    )

    with pytest.raises(
        NucleiScannerError,
        match="output",
    ):
        run_nuclei_assessment(
            snapshot=snapshot,
            template_root=root,
            target_list_path=target_list,
            allow_local_network_access=False,
            nuclei_binary="nuclei",
            timeout_seconds=120,
            max_output_bytes=10,
        )


def test_runner_allows_empty_successful_output(
    monkeypatch,
    tmp_path,
):
    import subprocess

    from app.scanners.nuclei import (
        run_nuclei_assessment,
    )

    (
        root,
        _,
        snapshot,
        target_list,
    ) = _prepared_snapshot(
        tmp_path
    )

    def fake_run(
        command,
        **kwargs,
    ):
        return subprocess.CompletedProcess(
            args=command,
            returncode=0,
            stdout=b"",
            stderr=b"informational message\n",
        )

    monkeypatch.setattr(
        "app.scanners.nuclei.subprocess.run",
        fake_run,
    )

    result = run_nuclei_assessment(
        snapshot=snapshot,
        template_root=root,
        target_list_path=target_list,
        allow_local_network_access=False,
        nuclei_binary="nuclei",
        timeout_seconds=120,
        max_output_bytes=1_000_000,
    )

    assert result.raw_jsonl == b""

    assert (
        result.detection_candidates
        == ()
    )


def test_runner_pins_nuclei_template_manager_to_snapshot_root(
    monkeypatch,
    tmp_path,
):
    import subprocess

    from app.scanners.nuclei import (
        run_nuclei_assessment,
    )

    (
        root,
        _,
        snapshot,
        target_list,
    ) = _prepared_snapshot(
        tmp_path
    )

    # Simulate an unsafe/stale inherited worker setting.
    monkeypatch.setenv(
        "NUCLEI_TEMPLATES_DIR",
        "/tmp/untrusted-nuclei-templates",
    )

    captured = {}

    def fake_run(
        command,
        **kwargs,
    ):
        captured["env"] = kwargs["env"]

        return subprocess.CompletedProcess(
            args=command,
            returncode=0,
            stdout=b"",
            stderr=b"",
        )

    monkeypatch.setattr(
        "app.scanners.nuclei.subprocess.run",
        fake_run,
    )

    run_nuclei_assessment(
        snapshot=snapshot,
        template_root=root,
        target_list_path=target_list,
        allow_local_network_access=False,
        nuclei_binary="nuclei",
        timeout_seconds=120,
        max_output_bytes=1_000_000,
    )

    assert captured["env"][
        "NUCLEI_TEMPLATES_DIR"
    ] == str(
        root.resolve()
    )
