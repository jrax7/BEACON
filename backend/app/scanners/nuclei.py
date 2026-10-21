from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import subprocess

from app.models.nuclei_template_snapshot import (
    NucleiTemplateSnapshot,
)


class NucleiScannerError(RuntimeError):
    """Raised when governed Nuclei execution cannot proceed safely."""


def _resolve_template_root(
    template_root: Path,
) -> Path:
    root = Path(
        template_root
    )

    if not root.exists():
        raise NucleiScannerError(
            "Nuclei template root is missing."
        )

    if not root.is_dir():
        raise NucleiScannerError(
            "Nuclei template root is not a directory."
        )

    return root.resolve()


def _snapshot_entry_path(
    entry: dict,
) -> str:
    value = entry.get(
        "template_path"
    )

    if not isinstance(
        value,
        str,
    ):
        raise NucleiScannerError(
            "Nuclei snapshot template path is invalid."
        )

    value = value.strip()

    if not value:
        raise NucleiScannerError(
            "Nuclei snapshot template path is empty."
        )

    if "\\" in value:
        raise NucleiScannerError(
            "Nuclei snapshot template path is unsafe."
        )

    if value.startswith("/"):
        raise NucleiScannerError(
            "Nuclei snapshot template path is unsafe."
        )

    if "//" in value:
        raise NucleiScannerError(
            "Nuclei snapshot template path is unsafe."
        )

    parts = value.split("/")

    if any(
        part in {
            "",
            ".",
            "..",
        }
        for part in parts
    ):
        raise NucleiScannerError(
            "Nuclei snapshot template path is unsafe."
        )

    return value


def _snapshot_entry_digest(
    entry: dict,
) -> str:
    value = entry.get(
        "template_revision_or_digest"
    )

    if not isinstance(
        value,
        str,
    ):
        raise NucleiScannerError(
            "Nuclei template digest is invalid."
        )

    value = value.strip().lower()

    if (
        len(value) != 64
        or any(
            character not in "0123456789abcdef"
            for character in value
        )
    ):
        raise NucleiScannerError(
            "Nuclei template digest is invalid."
        )

    return value


def resolve_snapshot_template_paths(
    *,
    snapshot: NucleiTemplateSnapshot,
    template_root: Path,
) -> tuple[Path, ...]:
    """Resolve and verify only files frozen in the approved snapshot."""

    root = _resolve_template_root(
        template_root
    )

    manifest = snapshot.template_manifest

    if not isinstance(
        manifest,
        list,
    ):
        raise NucleiScannerError(
            "Nuclei snapshot manifest is invalid."
        )

    resolved_paths: list[Path] = []

    for entry in manifest:
        if not isinstance(
            entry,
            dict,
        ):
            raise NucleiScannerError(
                "Nuclei snapshot manifest entry is invalid."
            )

        relative_path = _snapshot_entry_path(
            entry
        )

        expected_digest = _snapshot_entry_digest(
            entry
        )

        candidate = (
            root
            / relative_path
        )

        try:
            resolved = candidate.resolve(
                strict=True
            )
        except FileNotFoundError as exc:
            raise NucleiScannerError(
                "Nuclei snapshot template file is missing."
            ) from exc

        try:
            resolved.relative_to(
                root
            )
        except ValueError as exc:
            raise NucleiScannerError(
                "Nuclei snapshot template path escapes "
                "the approved template root."
            ) from exc

        if not resolved.is_file():
            raise NucleiScannerError(
                "Nuclei snapshot template is not a file."
            )

        actual_digest = hashlib.sha256(
            resolved.read_bytes()
        ).hexdigest()

        if actual_digest != expected_digest:
            raise NucleiScannerError(
                "Nuclei snapshot template digest mismatch."
            )

        resolved_paths.append(
            resolved
        )

    return tuple(
        resolved_paths
    )


def build_nuclei_command(
    *,
    snapshot: NucleiTemplateSnapshot,
    template_root: Path,
    target_list_path: Path,
    allow_local_network_access: bool,
    nuclei_binary: str,
) -> list[str]:
    """Build a governed Nuclei command from one immutable snapshot."""

    if (
        not isinstance(
            snapshot.template_manifest,
            list,
        )
        or not snapshot.template_manifest
    ):
        raise NucleiScannerError(
            "Nuclei snapshot is empty."
        )

    target_list = Path(
        target_list_path
    )

    if (
        not target_list.exists()
        or not target_list.is_file()
    ):
        raise NucleiScannerError(
            "Nuclei target list is missing."
        )

    target_list = target_list.resolve()

    templates = (
        resolve_snapshot_template_paths(
            snapshot=snapshot,
            template_root=template_root,
        )
    )

    if not templates:
        raise NucleiScannerError(
            "Nuclei snapshot is empty."
        )

    command = [
        nuclei_binary,
        "-jsonl",
        "-silent",
        "-no-color",
        "-omit-template",
        "-omit-raw",
        "-disable-update-check",
        "-no-interactsh",
        "-disable-unsigned-templates",
        "-no-stdin",
        "-no-httpx",
    ]

    if not allow_local_network_access:
        command.append(
            "-restrict-local-network-access"
        )

    command.extend(
        [
            "-list",
            str(
                target_list
            ),
        ]
    )

    for template in templates:
        command.extend(
            [
                "-templates",
                str(
                    template
                ),
            ]
        )

    return command


@dataclass(frozen=True)
class NucleiDetectionCandidate:
    """One structured Nuclei detection awaiting normalization."""

    template_id: str
    template_revision_or_digest: str
    template_source: str
    template_path: str

    template_name: str | None
    template_severity: str
    template_tags: tuple[str, ...]
    protocol: str

    matcher_name: str | None
    extractor_name: str | None

    host: str | None
    matched_at: str | None
    ip: str | None
    timestamp: str | None

    extracted_results: tuple[str, ...]


@dataclass(frozen=True)
class NucleiAssessmentResult:
    """Parsed Nuclei evidence without canonical Finding creation."""

    raw_jsonl: bytes
    detection_candidates: tuple[
        NucleiDetectionCandidate,
        ...,
    ]


def _optional_event_string(
    event: dict,
    key: str,
) -> str | None:
    value = event.get(
        key
    )

    if not isinstance(
        value,
        str,
    ):
        return None

    value = value.strip()

    return value or None


def _snapshot_manifest_by_template_id(
    snapshot: NucleiTemplateSnapshot,
) -> dict[str, dict]:
    manifest = snapshot.template_manifest

    if not isinstance(
        manifest,
        list,
    ):
        raise NucleiScannerError(
            "Nuclei snapshot manifest is invalid."
        )

    by_template_id: dict[str, dict] = {}

    for entry in manifest:
        if not isinstance(
            entry,
            dict,
        ):
            raise NucleiScannerError(
                "Nuclei snapshot manifest entry is invalid."
            )

        template_id = entry.get(
            "template_id"
        )

        if (
            not isinstance(
                template_id,
                str,
            )
            or not template_id.strip()
        ):
            raise NucleiScannerError(
                "Nuclei snapshot template id is invalid."
            )

        template_id = template_id.strip()

        if template_id in by_template_id:
            raise NucleiScannerError(
                "Nuclei snapshot contains duplicate "
                f"template id: {template_id!r}."
            )

        by_template_id[
            template_id
        ] = entry

    return by_template_id


def _snapshot_string(
    entry: dict,
    key: str,
) -> str:
    value = entry.get(
        key
    )

    if (
        not isinstance(
            value,
            str,
        )
        or not value.strip()
    ):
        raise NucleiScannerError(
            "Nuclei snapshot provenance is invalid."
        )

    return value.strip()


def _snapshot_string_tuple(
    entry: dict,
    key: str,
) -> tuple[str, ...]:
    value = entry.get(
        key
    )

    if not isinstance(
        value,
        list,
    ):
        raise NucleiScannerError(
            "Nuclei snapshot provenance is invalid."
        )

    normalized = []

    for item in value:
        if not isinstance(
            item,
            str,
        ):
            raise NucleiScannerError(
                "Nuclei snapshot provenance is invalid."
            )

        item = item.strip()

        if item:
            normalized.append(
                item
            )

    return tuple(
        normalized
    )


def _event_template_name(
    event: dict,
) -> str | None:
    info = event.get(
        "info"
    )

    if not isinstance(
        info,
        dict,
    ):
        return None

    value = info.get(
        "name"
    )

    if not isinstance(
        value,
        str,
    ):
        return None

    value = value.strip()

    return value or None


def _event_extracted_results(
    event: dict,
) -> tuple[str, ...]:
    value = event.get(
        "extracted-results"
    )

    if not isinstance(
        value,
        list,
    ):
        return ()

    normalized = []

    for item in value:
        if isinstance(
            item,
            str,
        ):
            normalized.append(
                item
            )

    return tuple(
        normalized
    )


def parse_nuclei_jsonl(
    *,
    raw_jsonl: bytes,
    snapshot: NucleiTemplateSnapshot,
    max_output_bytes: int,
) -> NucleiAssessmentResult:
    """Parse bounded Nuclei JSONL using snapshot provenance."""

    if max_output_bytes <= 0:
        raise NucleiScannerError(
            "Nuclei output limit must be positive."
        )

    if len(raw_jsonl) > max_output_bytes:
        raise NucleiScannerError(
            "Nuclei output exceeded the configured limit."
        )

    snapshot_entries = (
        _snapshot_manifest_by_template_id(
            snapshot
        )
    )

    detections: list[
        NucleiDetectionCandidate
    ] = []

    for raw_line in raw_jsonl.splitlines():
        if not raw_line.strip():
            continue

        try:
            event = json.loads(
                raw_line.decode(
                    "utf-8"
                )
            )
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
        ) as exc:
            raise NucleiScannerError(
                "Nuclei JSONL output contains invalid JSON."
            ) from exc

        if not isinstance(
            event,
            dict,
        ):
            raise NucleiScannerError(
                "Nuclei JSON event must be an object."
            )

        if event.get(
            "matcher-status"
        ) is False:
            continue

        template_id = event.get(
            "template-id"
        )

        if (
            not isinstance(
                template_id,
                str,
            )
            or not template_id.strip()
        ):
            raise NucleiScannerError(
                "Nuclei detection is missing a template id."
            )

        template_id = template_id.strip()

        snapshot_entry = (
            snapshot_entries.get(
                template_id
            )
        )

        if snapshot_entry is None:
            raise NucleiScannerError(
                "Nuclei detection references a template "
                "outside the approved snapshot."
            )

        detections.append(
            NucleiDetectionCandidate(
                template_id=template_id,
                template_revision_or_digest=(
                    _snapshot_string(
                        snapshot_entry,
                        "template_revision_or_digest",
                    )
                ),
                template_source=(
                    _snapshot_string(
                        snapshot_entry,
                        "template_source",
                    )
                ),
                template_path=(
                    _snapshot_string(
                        snapshot_entry,
                        "template_path",
                    )
                ),
                template_name=(
                    _event_template_name(
                        event
                    )
                ),
                template_severity=(
                    _snapshot_string(
                        snapshot_entry,
                        "template_severity",
                    )
                ),
                template_tags=(
                    _snapshot_string_tuple(
                        snapshot_entry,
                        "template_tags",
                    )
                ),
                protocol=(
                    _snapshot_string(
                        snapshot_entry,
                        "protocol",
                    )
                ),
                matcher_name=(
                    _optional_event_string(
                        event,
                        "matcher-name",
                    )
                ),
                extractor_name=(
                    _optional_event_string(
                        event,
                        "extractor-name",
                    )
                ),
                host=(
                    _optional_event_string(
                        event,
                        "host",
                    )
                ),
                matched_at=(
                    _optional_event_string(
                        event,
                        "matched-at",
                    )
                ),
                ip=(
                    _optional_event_string(
                        event,
                        "ip",
                    )
                ),
                timestamp=(
                    _optional_event_string(
                        event,
                        "timestamp",
                    )
                ),
                extracted_results=(
                    _event_extracted_results(
                        event
                    )
                ),
            )
        )

    return NucleiAssessmentResult(
        raw_jsonl=raw_jsonl,
        detection_candidates=tuple(
            detections
        ),
    )


def run_nuclei_assessment(
    *,
    snapshot: NucleiTemplateSnapshot,
    template_root: Path,
    target_list_path: Path,
    allow_local_network_access: bool,
    nuclei_binary: str,
    timeout_seconds: int,
    max_output_bytes: int,
) -> NucleiAssessmentResult:
    """Execute one governed Nuclei assessment."""

    if timeout_seconds <= 0:
        raise NucleiScannerError(
            "Nuclei timeout must be positive."
        )

    if max_output_bytes <= 0:
        raise NucleiScannerError(
            "Nuclei output limit must be positive."
        )

    command = build_nuclei_command(
        snapshot=snapshot,
        template_root=template_root,
        target_list_path=target_list_path,
        allow_local_network_access=(
            allow_local_network_access
        ),
        nuclei_binary=nuclei_binary,
    )

    environment = os.environ.copy()

    environment.update(
        {
            "LC_ALL": "C",
            "LANG": "C",
            "NUCLEI_TEMPLATES_DIR": str(
                Path(
                    template_root
                ).resolve()
            ),
        }
    )

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            check=False,
            timeout=timeout_seconds,
            stdin=subprocess.DEVNULL,
            env=environment,
        )
    except FileNotFoundError as exc:
        raise NucleiScannerError(
            "Nuclei executable was not found."
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise NucleiScannerError(
            "Nuclei assessment timed out."
        ) from exc

    if completed.returncode != 0:
        raise NucleiScannerError(
            "Nuclei assessment failed "
            f"with exit code {completed.returncode}."
        )

    raw_jsonl = completed.stdout

    if not isinstance(
        raw_jsonl,
        bytes,
    ):
        raise NucleiScannerError(
            "Nuclei output was not returned as bytes."
        )

    if len(raw_jsonl) > max_output_bytes:
        raise NucleiScannerError(
            "Nuclei output exceeded the configured limit."
        )

    return parse_nuclei_jsonl(
        raw_jsonl=raw_jsonl,
        snapshot=snapshot,
        max_output_bytes=max_output_bytes,
    )
