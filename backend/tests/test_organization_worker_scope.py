from __future__ import annotations

import ast
from pathlib import Path
import re


BACKEND = (
    Path(__file__)
    .resolve()
    .parents[1]
)


def read(path: str) -> str:
    return (
        BACKEND
        / path
    ).read_text(
        encoding="utf-8",
    )


def compact(path: str) -> str:
    return re.sub(
        r"\s+",
        "",
        read(path),
    )


def test_report_worker_audit_uses_persisted_scan_org() -> None:
    source = compact(
        "app/reporting/tasks.py"
    )

    assert (
        "organization_id=scan.organization_id"
        in source
    )


def test_legacy_worker_audits_are_organization_aware() -> None:
    source = compact(
        "app/tasks.py"
    )

    assert (
        "organization_id="
        in source
    )

    assert (
        "scan.organization_id"
        in source
        or
        "progress_scan.organization_id"
        in source
        or
        "failed_scan.organization_id"
        in source
    )


def test_engine_v2_orchestration_verifies_scan_target_org_match() -> None:
    source = compact(
        "app/assessment/orchestration.py"
    )

    assert (
        "scan.organization_id"
        in source
    )

    assert (
        "target.organization_id"
        in source
    )

    assert (
        (
            "scan.organization_id"
            "!=target.organization_id"
        )
        in source
        or
        (
            "target.organization_id"
            "!=scan.organization_id"
        )
        in source
    )


def function_arguments(
    path: str,
) -> dict[str, set[str]]:
    tree = ast.parse(
        read(path)
    )

    result = {}

    for node in ast.walk(tree):
        if not isinstance(
            node,
            (
                ast.FunctionDef,
                ast.AsyncFunctionDef,
            ),
        ):
            continue

        arguments = {
            arg.arg
            for arg in (
                list(
                    node.args.posonlyargs
                )
                + list(
                    node.args.args
                )
                + list(
                    node.args.kwonlyargs
                )
            )
        }

        result[
            node.name
        ] = arguments

    return result


def test_worker_entrypoints_do_not_accept_client_org_scope() -> None:
    interesting = {
        "run_basic_scan",
        "run_assessment_v2",
        "generate_scan_report",
    }

    discovered = {}

    for path in (
        "app/tasks.py",
        "app/tasks_v2.py",
        "app/reporting/tasks.py",
    ):
        functions = function_arguments(
            path
        )

        for name in interesting:
            if name in functions:
                discovered[
                    name
                ] = functions[
                    name
                ]


    assert discovered, (
        "Expected worker entrypoints "
        "were not discovered."
    )


    for name, arguments in (
        discovered.items()
    ):
        assert (
            "organization_id"
            not in arguments
        ), (
            f"{name} must derive tenant "
            "scope from persisted state."
        )
