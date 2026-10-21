from __future__ import annotations

import inspect
import re

from app.routers import assessments
from app.routers import reports
from app.routers import scans
from app.routers import targets


FORBIDDEN_CURRENT_USER_BOUNDARIES = (
    "Target.user_id == current_user.id",
    "Scan.user_id == current_user.id",
)


def compact(callable_object) -> str:
    return re.sub(
        r"\s+",
        " ",
        inspect.getsource(
            callable_object
        ),
    )


def assert_no_user_tenant_boundary(
    callable_object,
) -> None:
    source = compact(
        callable_object
    )

    for forbidden in (
        FORBIDDEN_CURRENT_USER_BOUNDARIES
    ):
        assert forbidden not in source


def test_target_ownership_helper_is_organization_scoped() -> None:
    assert_no_user_tenant_boundary(
        targets.get_owned_target
    )

    source = compact(
        targets.get_owned_target
    )

    assert "Target.organization_id" in source


def test_scan_ownership_helpers_are_organization_scoped() -> None:
    for helper in (
        scans.get_owned_scan,
        scans.get_owned_scans,
    ):
        assert_no_user_tenant_boundary(
            helper
        )

        source = compact(
            helper
        )

        assert "Scan.organization_id" in source


def test_assessment_ownership_helper_is_organization_scoped() -> None:
    assert_no_user_tenant_boundary(
        assessments._get_owned_assessment
    )

    source = compact(
        assessments._get_owned_assessment
    )

    assert "Scan.organization_id" in source


def test_report_ownership_helpers_do_not_restore_user_tenancy() -> None:
    for helper in (
        reports.get_owned_scan,
        reports.get_owned_report,
        reports.get_owned_reports,
    ):
        assert_no_user_tenant_boundary(
            helper
        )


def test_public_operational_modules_do_not_restore_current_user_boundary() -> None:
    for module in (
        targets,
        scans,
        assessments,
        reports,
    ):
        source = re.sub(
            r"\s+",
            " ",
            inspect.getsource(
                module
            ),
        )

        for forbidden in (
            FORBIDDEN_CURRENT_USER_BOUNDARIES
        ):
            assert forbidden not in source
