from __future__ import annotations

from pathlib import Path


def test_auth_mail_task_routes_to_control_queue() -> None:
    from app.celery_app import celery_app

    assert (
        celery_app.conf.task_routes[
            "beacon.send_auth_email"
        ]["queue"]
        == "control"
    )


def test_control_worker_consumes_control_and_report() -> None:
    source = Path(
        "/app/compose.yaml"
    ).read_text(
        encoding="utf-8",
    )

    assert "--queues=control,report" in source
    assert "--queues=scanner" in source


def test_auth_mail_task_not_routed_to_scanner() -> None:
    from app.celery_app import celery_app

    route = celery_app.conf.task_routes[
        "beacon.send_auth_email"
    ]

    assert route["queue"] != "scanner"


def test_reporting_route_remains_report_queue() -> None:
    from app.celery_app import celery_app

    assert (
        celery_app.conf.task_routes[
            "beacon.generate_scan_report"
        ]["queue"]
        == "report"
    )


def test_auth_mail_tasks_supply_branded_message_context() -> None:
    source = (
        Path(__file__).resolve().parents[1]
        / "app"
        / "auth"
        / "mail_tasks.py"
    ).read_text(
        encoding="utf-8",
    )

    for token in (
        '"recipient_name"',
        '"organization_name"',
        '"workspace_role"',
        '"inviter_name"',
    ):
        assert token in source
