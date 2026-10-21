from app.assessment.handoff import (
    WebEndpoint,
    WebEndpointInventory,
)


def _inventory():
    return WebEndpointInventory(
        endpoints=(
            WebEndpoint(
                url="https://portal.example.com/",
                method="GET",
                discovery_method="katana",
            ),
            WebEndpoint(
                url="https://portal.example.com/login",
                method="POST",
                parameter_names=(
                    "username",
                    "password",
                ),
                discovery_method="form",
            ),
        )
    )


def test_zap_v2_parser_returns_detection_candidates_not_findings():
    from app.scanners.zap import (
        ZapDetectionCandidate,
        parse_zap_alerts,
    )

    alerts = [
        {
            "pluginId": "10021",
            "alert": "X-Content-Type-Options Header Missing",
            "risk": "Low",
            "confidence": "Medium",
            "url": "https://portal.example.com/login",
            "method": "GET",
            "param": "",
            "evidence": "",
            "description": "The response is missing a security header.",
            "solution": "Set the X-Content-Type-Options header.",
            "reference": "https://www.zaproxy.org/",
            "cweid": "693",
            "wascid": "15",
            "sourceid": "3",
        }
    ]

    candidates = parse_zap_alerts(
        alerts=alerts,
        authorized_host="portal.example.com",
    )

    assert len(candidates) == 1

    candidate = candidates[0]

    assert isinstance(
        candidate,
        ZapDetectionCandidate,
    )

    assert candidate.plugin_id == "10021"

    assert candidate.title == (
        "X-Content-Type-Options Header Missing"
    )

    assert candidate.severity == "low"

    assert candidate.confidence == "medium"

    assert candidate.affected_url == (
        "https://portal.example.com/login"
    )

    assert candidate.cwe_id == "CWE-693"

    assert not hasattr(
        candidate,
        "scan_id",
    )

    assert not hasattr(
        candidate,
        "tool_run_id",
    )


def test_zap_v2_parser_excludes_alerts_outside_exact_authorized_host():
    from app.scanners.zap import (
        parse_zap_alerts,
    )

    alerts = [
        {
            "pluginId": "10021",
            "alert": "Authorized observation",
            "risk": "Low",
            "confidence": "Medium",
            "url": "https://portal.example.com/",
        },
        {
            "pluginId": "10021",
            "alert": "External redirect observation",
            "risk": "Low",
            "confidence": "Medium",
            "url": "https://login.microsoftonline.com/",
        },
        {
            "pluginId": "10021",
            "alert": "Sibling observation",
            "risk": "Low",
            "confidence": "Medium",
            "url": "https://api.example.com/",
        },
    ]

    candidates = parse_zap_alerts(
        alerts=alerts,
        authorized_host="portal.example.com",
    )

    assert len(candidates) == 1

    assert candidates[0].affected_url == (
        "https://portal.example.com/"
    )


def test_existing_legacy_passive_wrapper_still_exists():
    from app.scanners.zap import (
        ZapClient,
    )

    assert hasattr(
        ZapClient,
        "run_passive_scan",
    )


def test_zap_v2_assessment_interface_consumes_web_inventory():
    from app.scanners.zap import (
        ZapAssessmentRequest,
    )

    request = ZapAssessmentRequest(
        authorized_host="portal.example.com",
        web_inventory=_inventory(),
        policy_version="beacon-quick-v1",
        active_scan_enabled=False,
    )

    assert request.authorized_host == (
        "portal.example.com"
    )

    assert request.web_inventory == (
        _inventory()
    )

    assert request.policy_version == (
        "beacon-quick-v1"
    )

    assert request.active_scan_enabled is False


def test_zap_v2_candidate_preserves_scanner_evidence_metadata():
    from app.scanners.zap import (
        parse_zap_alerts,
    )

    alerts = [
        {
            "pluginId": "40018",
            "alert": "SQL Injection",
            "risk": "High",
            "confidence": "Medium",
            "url": (
                "https://portal.example.com/"
                "search?q=test"
            ),
            "method": "GET",
            "param": "q",
            "evidence": "SQL syntax error",
            "attack": "' OR '1'='1",
            "description": (
                "The parameter appears vulnerable "
                "to SQL injection."
            ),
            "solution": (
                "Use parameterized queries."
            ),
            "reference": (
                "https://www.zaproxy.org/"
            ),
            "cweid": "89",
            "wascid": "19",
            "messageId": "1234",
            "sourceid": "3",
        }
    ]

    candidates = parse_zap_alerts(
        alerts=alerts,
        authorized_host="portal.example.com",
    )

    assert len(candidates) == 1

    candidate = candidates[0]

    assert candidate.http_method == "GET"
    assert candidate.parameter == "q"

    assert candidate.evidence == (
        "SQL syntax error"
    )

    assert candidate.attack == (
        "' OR '1'='1"
    )

    assert candidate.description == (
        "The parameter appears vulnerable "
        "to SQL injection."
    )

    assert candidate.remediation == (
        "Use parameterized queries."
    )

    assert candidate.reference == (
        "https://www.zaproxy.org/"
    )

    assert candidate.message_id == "1234"
    assert candidate.source_id == "3"
    assert candidate.wasc_id == "19"


def test_zap_v2_parser_normalizes_zap_risk_vocabulary():
    from app.scanners.zap import (
        parse_zap_alerts,
    )

    alerts = [
        {
            "pluginId": "1",
            "alert": "Info observation",
            "risk": "Info",
            "url": "https://portal.example.com/a",
        },
        {
            "pluginId": "2",
            "alert": "Unknown observation",
            "risk": "Unexpected-Risk",
            "url": "https://portal.example.com/b",
        },
    ]

    candidates = parse_zap_alerts(
        alerts=alerts,
        authorized_host="portal.example.com",
    )

    assert tuple(
        candidate.severity
        for candidate in candidates
    ) == (
        "informational",
        "informational",
    )


def test_zap_v2_passive_runner_uses_authorized_inventory_only():
    from app.assessment.handoff import (
        WebEndpoint,
        WebEndpointInventory,
    )
    from app.scanners.zap import (
        ZapAssessmentRequest,
        ZapAssessmentResult,
        ZapClient,
    )

    class RecordingZapClient(ZapClient):
        def __init__(self):
            self.calls = []

        def wait_until_ready(self):
            self.calls.append(
                ("wait_until_ready",)
            )
            return "2.16.1"

        def start_new_session(self):
            self.calls.append(
                ("start_new_session",)
            )

        def access_target(self, target_url):
            self.calls.append(
                (
                    "access_target",
                    target_url,
                )
            )

        def start_spider(self, target_url):
            self.calls.append(
                (
                    "start_spider",
                    target_url,
                )
            )
            return "spider-7"

        def wait_for_spider(self, scan_id):
            self.calls.append(
                (
                    "wait_for_spider",
                    scan_id,
                )
            )

        def wait_for_passive_scan(self):
            self.calls.append(
                ("wait_for_passive_scan",)
            )

        def get_alerts(self, target_url):
            self.calls.append(
                (
                    "get_alerts",
                    target_url,
                )
            )

            return [
                {
                    "pluginId": "10021",
                    "alert": "In-scope observation",
                    "risk": "Low",
                    "confidence": "Medium",
                    "url": (
                        "https://portal.example.com/"
                        "login"
                    ),
                    "cweid": "693",
                },
                {
                    "pluginId": "10021",
                    "alert": "External observation",
                    "risk": "Low",
                    "confidence": "Medium",
                    "url": (
                        "https://login."
                        "microsoftonline.com/"
                    ),
                    "cweid": "693",
                },
            ]

    inventory = WebEndpointInventory(
        endpoints=(
            WebEndpoint(
                url=(
                    "https://login."
                    "microsoftonline.com/"
                ),
                method="GET",
                discovery_method="redirect",
            ),
            WebEndpoint(
                url="https://portal.example.com/login",
                method="GET",
                discovery_method="katana",
            ),
            WebEndpoint(
                url="https://portal.example.com/account",
                method="GET",
                discovery_method="katana",
            ),
        )
    )

    request = ZapAssessmentRequest(
        authorized_host="portal.example.com",
        web_inventory=inventory,
        policy_version="beacon-quick-v1",
        active_scan_enabled=False,
    )

    client = RecordingZapClient()

    result = client.run_assessment(
        request
    )

    assert isinstance(
        result,
        ZapAssessmentResult,
    )

    assert result.version == "2.16.1"

    assert result.policy_version == (
        "beacon-quick-v1"
    )

    assert result.active_scan_enabled is False

    assert result.included_endpoint_count == 2
    assert result.excluded_endpoint_count == 1

    assert result.spider_scan_ids == (
        "spider-7",
    )

    assert len(result.raw_alerts) == 2

    assert len(result.detections) == 1

    assert result.detections[0].affected_url == (
        "https://portal.example.com/login"
    )

    assert (
        "https://login.microsoftonline.com/"
        not in tuple(
            call[1]
            for call in client.calls
            if (
                call[0]
                in {
                    "access_target",
                    "start_spider",
                    "get_alerts",
                }
            )
        )
    )

    assert (
        "access_target",
        "https://portal.example.com/",
    ) in client.calls

    assert (
        "start_spider",
        "https://portal.example.com/",
    ) in client.calls

    assert (
        "wait_for_spider",
        "spider-7",
    ) in client.calls

    assert (
        "wait_for_passive_scan",
    ) in client.calls

    assert (
        "get_alerts",
        "https://portal.example.com/",
    ) in client.calls


def test_zap_v2_passive_runner_refuses_empty_authorized_scope():
    from app.assessment.handoff import (
        WebEndpoint,
        WebEndpointInventory,
    )
    from app.scanners.zap import (
        ZapAssessmentRequest,
        ZapClient,
        ZapScannerError,
    )

    class NoNetworkZapClient(ZapClient):
        def __init__(self):
            pass

        def wait_until_ready(self):
            raise AssertionError(
                "ZAP runtime must not be contacted "
                "for an empty authorized scope."
            )

    request = ZapAssessmentRequest(
        authorized_host="portal.example.com",
        web_inventory=WebEndpointInventory(
            endpoints=(
                WebEndpoint(
                    url="https://api.example.com/",
                    method="GET",
                    discovery_method="katana",
                ),
            )
        ),
        policy_version="beacon-quick-v1",
        active_scan_enabled=False,
    )

    client = NoNetworkZapClient()

    import pytest

    with pytest.raises(
        ZapScannerError,
        match="authorized ZAP scope",
    ):
        client.run_assessment(
            request
        )


def test_zap_runtime_configures_only_explicit_locked_rules():
    from app.assessment.authorization import (
        ActiveAuthorizationConfirmation,
    )
    from app.assessment.zap_policy import (
        resolve_zap_policy,
    )
    from app.scanners.zap import (
        ZapClient,
    )
    from datetime import (
        datetime,
        timezone,
    )

    confirmation = ActiveAuthorizationConfirmation(
        confirmed=True,
        confirmed_by_user_id=42,
        confirmed_at=datetime.now(timezone.utc),
        authorization_version="active-v1",
    )

    policy = resolve_zap_policy(
        profile_name="standard",
        active_confirmation=confirmation,
    )

    class RecordingZapClient(ZapClient):
        def __init__(self):
            self.calls = []

        def _request(
            self,
            path,
            parameters=None,
        ):
            self.calls.append(
                (
                    path,
                    dict(parameters or {}),
                )
            )

            return {}

    client = RecordingZapClient()

    client.configure_active_scan_policy(
        scan_policy_name=(
            "beacon-test-standard"
        ),
        policy=policy,
    )

    paths = tuple(
        path
        for path, _ in client.calls
    )

    assert (
        "/JSON/ascan/action/addScanPolicy/"
        in paths
    )

    assert (
        "/JSON/ascan/action/disableAllScanners/"
        in paths
    )

    assert (
        "/JSON/ascan/action/enableScanners/"
        in paths
    )

    assert (
        "/JSON/ascan/action/enableAllScanners/"
        not in paths
    )

    add_policy_call = next(
        parameters
        for path, parameters in client.calls
        if path
        == "/JSON/ascan/action/addScanPolicy/"
    )

    assert add_policy_call == {
        "scanPolicyName": (
            "beacon-test-standard"
        ),
        "alertThreshold": "OFF",
        "attackStrength": "LOW",
    }

    enable_call = next(
        parameters
        for path, parameters in client.calls
        if path
        == "/JSON/ascan/action/enableScanners/"
    )

    assert enable_call == {
        "ids": (
            "6,20019,40003,40008,40012,"
            "40018,40032,40034,40035,90021"
        ),
        "scanPolicyName": (
            "beacon-test-standard"
        ),
    }

    threshold_calls = [
        parameters
        for path, parameters in client.calls
        if path
        == (
            "/JSON/ascan/action/"
            "setScannerAlertThreshold/"
        )
    ]

    strength_calls = [
        parameters
        for path, parameters in client.calls
        if path
        == (
            "/JSON/ascan/action/"
            "setScannerAttackStrength/"
        )
    ]

    assert len(threshold_calls) == 10
    assert len(strength_calls) == 10

    assert {
        int(parameters["id"])
        for parameters in threshold_calls
    } == {
        rule.rule_id
        for rule in policy.active_rules
    }

    assert {
        int(parameters["id"])
        for parameters in strength_calls
    } == {
        rule.rule_id
        for rule in policy.active_rules
    }

    assert all(
        parameters["alertThreshold"]
        == "MEDIUM"
        for parameters in threshold_calls
    )

    assert all(
        parameters["attackStrength"]
        == "LOW"
        for parameters in strength_calls
    )

    assert all(
        parameters["scanPolicyName"]
        == "beacon-test-standard"
        for parameters in (
            threshold_calls
            + strength_calls
        )
    )


def test_quick_policy_cannot_configure_active_zap_runtime():
    from app.assessment.zap_policy import (
        resolve_zap_policy,
    )
    from app.scanners.zap import (
        ZapClient,
        ZapScannerError,
    )

    policy = resolve_zap_policy(
        profile_name="quick",
        active_confirmation=None,
    )

    class NoNetworkZapClient(ZapClient):
        def __init__(self):
            self.calls = []

        def _request(
            self,
            path,
            parameters=None,
        ):
            self.calls.append(
                (
                    path,
                    parameters,
                )
            )

            raise AssertionError(
                "Quick must not call the "
                "ZAP active-scan API."
            )

    client = NoNetworkZapClient()

    import pytest

    with pytest.raises(
        ZapScannerError,
        match="active",
    ):
        client.configure_active_scan_policy(
            scan_policy_name="beacon-test-quick",
            policy=policy,
        )

    assert client.calls == []


def test_zap_runtime_applies_bounded_active_scan_limits():
    from datetime import datetime, timezone

    from app.assessment.authorization import (
        ActiveAuthorizationConfirmation,
    )
    from app.assessment.zap_policy import (
        resolve_zap_policy,
    )
    from app.scanners.zap import ZapClient

    confirmation = ActiveAuthorizationConfirmation(
        confirmed=True,
        confirmed_by_user_id=42,
        confirmed_at=datetime.now(timezone.utc),
        authorization_version="active-v1",
    )

    policy = resolve_zap_policy(
        profile_name="standard",
        active_confirmation=confirmation,
    )

    class RecordingZapClient(ZapClient):
        def __init__(self):
            self.calls = []

        def _request(
            self,
            path,
            parameters=None,
        ):
            self.calls.append(
                (
                    path,
                    dict(parameters or {}),
                )
            )

            return {}

    client = RecordingZapClient()

    client.configure_active_scan_limits(
        policy=policy,
    )

    assert client.calls == [
        (
            (
                "/JSON/ascan/action/"
                "setOptionMaxRuleDurationInMins/"
            ),
            {
                "Integer": 2,
            },
        ),
        (
            (
                "/JSON/ascan/action/"
                "setOptionMaxScanDurationInMins/"
            ),
            {
                "Integer": 20,
            },
        ),
        (
            (
                "/JSON/ascan/action/"
                "setOptionMaxAlertsPerRule/"
            ),
            {
                "Integer": 20,
            },
        ),
    ]


def test_quick_cannot_configure_active_scan_limits():
    from app.assessment.zap_policy import (
        resolve_zap_policy,
    )
    from app.scanners.zap import (
        ZapClient,
        ZapScannerError,
    )

    policy = resolve_zap_policy(
        profile_name="quick",
        active_confirmation=None,
    )

    class NoNetworkZapClient(ZapClient):
        def __init__(self):
            self.calls = []

        def _request(
            self,
            path,
            parameters=None,
        ):
            self.calls.append(
                (
                    path,
                    parameters,
                )
            )

            raise AssertionError(
                "Quick must not configure "
                "active-scan runtime limits."
            )

    client = NoNetworkZapClient()

    import pytest

    with pytest.raises(
        ZapScannerError,
        match="active",
    ):
        client.configure_active_scan_limits(
            policy=policy,
        )

    assert client.calls == []


def test_zap_creates_fresh_exact_origin_context():
    from app.scanners.zap import (
        ZapClient,
    )

    class RecordingZapClient(ZapClient):
        def __init__(self):
            self.calls = []

        def _request(
            self,
            path,
            parameters=None,
        ):
            parameters = dict(
                parameters or {}
            )

            self.calls.append(
                (
                    path,
                    parameters,
                )
            )

            if path == (
                "/JSON/context/action/newContext/"
            ):
                return {
                    "contextId": "17",
                }

            return {}

    client = RecordingZapClient()

    context_id = client.create_assessment_context(
        context_name="beacon-assessment-123",
        authorized_host="portal.example.com",
        origins=(
            "https://portal.example.com/",
        ),
    )

    assert context_id == "17"

    assert client.calls == [
        (
            "/JSON/context/action/newContext/",
            {
                "contextName": (
                    "beacon-assessment-123"
                ),
            },
        ),
        (
            (
                "/JSON/context/action/"
                "includeInContext/"
            ),
            {
                "contextName": (
                    "beacon-assessment-123"
                ),
                "regex": (
                    "^https://portal"
                    r"\.example\.com(?:/.*)?$"
                ),
            },
        ),
        (
            (
                "/JSON/context/action/"
                "setContextInScope/"
            ),
            {
                "contextName": (
                    "beacon-assessment-123"
                ),
                "booleanInScope": "true",
            },
        ),
    ]


def test_zap_context_rejects_origin_outside_authorized_host():
    from app.scanners.zap import (
        ZapClient,
        ZapScannerError,
    )

    class NoNetworkZapClient(ZapClient):
        def __init__(self):
            self.calls = []

        def _request(
            self,
            path,
            parameters=None,
        ):
            self.calls.append(
                (
                    path,
                    parameters,
                )
            )

            raise AssertionError(
                "An unauthorized origin must "
                "not reach the ZAP API."
            )

    client = NoNetworkZapClient()

    import pytest

    with pytest.raises(
        ZapScannerError,
        match="authorized ZAP context",
    ):
        client.create_assessment_context(
            context_name=(
                "beacon-assessment-evil"
            ),
            authorized_host=(
                "portal.example.com"
            ),
            origins=(
                "https://portal.example.com/",
                "https://api.example.com/",
            ),
        )

    assert client.calls == []


def test_zap_active_scan_launch_requires_named_policy_and_context():
    from datetime import datetime, timezone

    from app.assessment.authorization import (
        ActiveAuthorizationConfirmation,
    )
    from app.assessment.zap_policy import (
        resolve_zap_policy,
    )
    from app.scanners.zap import (
        ZapClient,
    )

    confirmation = ActiveAuthorizationConfirmation(
        confirmed=True,
        confirmed_by_user_id=42,
        confirmed_at=datetime.now(timezone.utc),
        authorization_version="active-v1",
    )

    policy = resolve_zap_policy(
        profile_name="standard",
        active_confirmation=confirmation,
    )

    class RecordingZapClient(ZapClient):
        def __init__(self):
            self.calls = []

        def _request(
            self,
            path,
            parameters=None,
        ):
            parameters = dict(
                parameters or {}
            )

            self.calls.append(
                (
                    path,
                    parameters,
                )
            )

            return {
                "scan": "91",
            }

    client = RecordingZapClient()

    scan_id = client.start_active_scan(
        target_url="https://portal.example.com/",
        authorized_host="portal.example.com",
        context_id="17",
        scan_policy_name=(
            "beacon-assessment-123-standard"
        ),
        policy=policy,
    )

    assert scan_id == "91"

    assert client.calls == [
        (
            "/JSON/ascan/action/scan/",
            {
                "url": (
                    "https://portal.example.com/"
                ),
                "recurse": "true",
                "inScopeOnly": "true",
                "scanPolicyName": (
                    "beacon-assessment-123-standard"
                ),
                "contextId": "17",
            },
        ),
    ]


def test_zap_active_scan_rejects_target_outside_authorized_host():
    from datetime import datetime, timezone

    from app.assessment.authorization import (
        ActiveAuthorizationConfirmation,
    )
    from app.assessment.zap_policy import (
        resolve_zap_policy,
    )
    from app.scanners.zap import (
        ZapClient,
        ZapScannerError,
    )

    confirmation = ActiveAuthorizationConfirmation(
        confirmed=True,
        confirmed_by_user_id=42,
        confirmed_at=datetime.now(timezone.utc),
        authorization_version="active-v1",
    )

    policy = resolve_zap_policy(
        profile_name="standard",
        active_confirmation=confirmation,
    )

    class NoNetworkZapClient(ZapClient):
        def __init__(self):
            self.calls = []

        def _request(
            self,
            path,
            parameters=None,
        ):
            self.calls.append(
                (
                    path,
                    parameters,
                )
            )

            raise AssertionError(
                "Out-of-scope active target "
                "must not reach ZAP."
            )

    client = NoNetworkZapClient()

    import pytest

    with pytest.raises(
        ZapScannerError,
        match="authorized",
    ):
        client.start_active_scan(
            target_url=(
                "https://api.example.com/"
            ),
            authorized_host=(
                "portal.example.com"
            ),
            context_id="17",
            scan_policy_name=(
                "beacon-assessment-123-standard"
            ),
            policy=policy,
        )

    assert client.calls == []


def test_quick_policy_cannot_launch_zap_active_scan():
    from app.assessment.zap_policy import (
        resolve_zap_policy,
    )
    from app.scanners.zap import (
        ZapClient,
        ZapScannerError,
    )

    policy = resolve_zap_policy(
        profile_name="quick",
        active_confirmation=None,
    )

    class NoNetworkZapClient(ZapClient):
        def __init__(self):
            self.calls = []

        def _request(
            self,
            path,
            parameters=None,
        ):
            self.calls.append(
                (
                    path,
                    parameters,
                )
            )

            raise AssertionError(
                "Quick must never launch "
                "a ZAP active scan."
            )

    client = NoNetworkZapClient()

    import pytest

    with pytest.raises(
        ZapScannerError,
        match="active",
    ):
        client.start_active_scan(
            target_url=(
                "https://portal.example.com/"
            ),
            authorized_host=(
                "portal.example.com"
            ),
            context_id="17",
            scan_policy_name=(
                "beacon-assessment-123-quick"
            ),
            policy=policy,
        )

    assert client.calls == []


def test_zap_active_scan_waits_until_status_reaches_100(
    monkeypatch,
):
    import app.scanners.zap as zap_module

    from app.scanners.zap import (
        ZapClient,
    )

    class RecordingZapClient(ZapClient):
        def __init__(self):
            self.calls = []
            self.statuses = iter(
                (
                    "0",
                    "47",
                    "100",
                )
            )

        def _request(
            self,
            path,
            parameters=None,
        ):
            parameters = dict(
                parameters or {}
            )

            self.calls.append(
                (
                    path,
                    parameters,
                )
            )

            return {
                "status": next(
                    self.statuses
                ),
            }

    sleeps = []

    monkeypatch.setattr(
        zap_module.time,
        "sleep",
        lambda seconds: sleeps.append(
            seconds
        ),
    )

    client = RecordingZapClient()

    client.wait_for_active_scan(
        scan_id="91",
    )

    assert client.calls == [
        (
            "/JSON/ascan/view/status/",
            {
                "scanId": "91",
            },
        ),
        (
            "/JSON/ascan/view/status/",
            {
                "scanId": "91",
            },
        ),
        (
            "/JSON/ascan/view/status/",
            {
                "scanId": "91",
            },
        ),
    ]

    assert sleeps == [
        2,
        2,
    ]


def test_zap_active_scan_rejects_invalid_status(
    monkeypatch,
):
    import app.scanners.zap as zap_module

    from app.scanners.zap import (
        ZapClient,
        ZapScannerError,
    )

    import pytest

    invalid_statuses = (
        None,
        "",
        "banana",
        "-1",
        "101",
    )

    for invalid_status in invalid_statuses:
        class InvalidStatusZapClient(ZapClient):
            def __init__(self):
                self.calls = []

            def _request(
                self,
                path,
                parameters=None,
            ):
                parameters = dict(
                    parameters or {}
                )

                self.calls.append(
                    (
                        path,
                        parameters,
                    )
                )

                return {
                    "status": invalid_status,
                }

        monkeypatch.setattr(
            zap_module.time,
            "sleep",
            lambda seconds: (
                pytest.fail(
                    "Invalid ZAP status must "
                    "fail before sleeping."
                )
            ),
        )

        client = InvalidStatusZapClient()

        with pytest.raises(
            ZapScannerError,
            match="status",
        ):
            client.wait_for_active_scan(
                scan_id="91",
            )

        assert client.calls == [
            (
                "/JSON/ascan/view/status/",
                {
                    "scanId": "91",
                },
            ),
        ]


def test_zap_active_scan_has_bounded_default_timeout_configuration():
    from app.config import settings

    assert (
        settings.zap_active_scan_timeout_seconds
        == 2760.0
    )


def test_zap_active_scan_enforces_wall_clock_timeout(
    monkeypatch,
):
    import app.scanners.zap as zap_module

    from app.scanners.zap import (
        ZapClient,
        ZapScannerError,
    )

    class StuckZapClient(ZapClient):
        def __init__(self):
            self.calls = []

        def _request(
            self,
            path,
            parameters=None,
        ):
            parameters = dict(
                parameters or {}
            )

            self.calls.append(
                (
                    path,
                    parameters,
                )
            )

            return {
                "status": "47",
            }

    monotonic_values = iter(
        (
            100.0,
            102.0,
            106.0,
        )
    )

    monkeypatch.setattr(
        zap_module.time,
        "monotonic",
        lambda: next(
            monotonic_values
        ),
    )

    sleeps = []

    monkeypatch.setattr(
        zap_module.time,
        "sleep",
        lambda seconds: sleeps.append(
            seconds
        ),
    )

    client = StuckZapClient()

    import pytest

    with pytest.raises(
        ZapScannerError,
        match="timed out",
    ):
        client.wait_for_active_scan(
            scan_id="91",
            timeout_seconds=5.0,
        )

    assert client.calls == [
        (
            "/JSON/ascan/view/status/",
            {
                "scanId": "91",
            },
        ),
        (
            "/JSON/ascan/view/status/",
            {
                "scanId": "91",
            },
        ),
        (
            "/JSON/ascan/action/stop/",
            {
                "scanId": "91",
            },
        ),
    ]

    assert sleeps == [
        2,
    ]


def test_zap_timeout_stop_failure_does_not_hide_timeout(
    monkeypatch,
):
    import app.scanners.zap as zap_module

    from app.scanners.zap import (
        ZapClient,
        ZapScannerError,
    )

    class StopFailureZapClient(ZapClient):
        def __init__(self):
            self.calls = []

        def _request(
            self,
            path,
            parameters=None,
        ):
            parameters = dict(
                parameters or {}
            )

            self.calls.append(
                (
                    path,
                    parameters,
                )
            )

            if path == (
                "/JSON/ascan/action/stop/"
            ):
                raise RuntimeError(
                    "simulated ZAP stop failure"
                )

            return {
                "status": "47",
            }

    monotonic_values = iter(
        (
            100.0,
            106.0,
        )
    )

    monkeypatch.setattr(
        zap_module.time,
        "monotonic",
        lambda: next(
            monotonic_values
        ),
    )

    import pytest

    monkeypatch.setattr(
        zap_module.time,
        "sleep",
        lambda seconds: pytest.fail(
            "Timeout should occur before sleeping."
        ),
    )

    client = StopFailureZapClient()

    with pytest.raises(
        ZapScannerError,
        match="timed out",
    ):
        client.wait_for_active_scan(
            scan_id="91",
            timeout_seconds=5.0,
        )

    assert client.calls == [
        (
            "/JSON/ascan/view/status/",
            {
                "scanId": "91",
            },
        ),
        (
            "/JSON/ascan/action/stop/",
            {
                "scanId": "91",
            },
        ),
    ]


def test_zap_active_request_carries_resolved_policy_and_execution_id():
    from datetime import datetime, timezone

    from app.assessment.authorization import (
        ActiveAuthorizationConfirmation,
    )
    from app.assessment.zap_policy import (
        resolve_zap_policy,
    )
    from app.scanners.zap import (
        ZapAssessmentRequest,
    )

    policy = resolve_zap_policy(
        profile_name="standard",
        active_confirmation=(
            ActiveAuthorizationConfirmation(
                confirmed=True,
                confirmed_by_user_id=42,
                confirmed_at=datetime.now(
                    timezone.utc
                ),
                authorization_version="active-v1",
            )
        ),
    )

    request = ZapAssessmentRequest(
        authorized_host="portal.example.com",
        web_inventory=_inventory(),
        policy_version=policy.policy_version,
        active_scan_enabled=True,
        active_policy=policy,
        execution_id="assessment-exec-123",
    )

    assert request.active_policy is policy

    assert request.execution_id == (
        "assessment-exec-123"
    )


def test_zap_active_runner_refuses_missing_resolved_policy_before_network():
    from app.scanners.zap import (
        ZapAssessmentRequest,
        ZapClient,
        ZapScannerError,
    )

    class NoNetworkZapClient(ZapClient):
        def __init__(self):
            self.calls = []

        def wait_until_ready(self):
            self.calls.append(
                ("wait_until_ready",)
            )

            raise AssertionError(
                "Active assessment validation "
                "must occur before contacting ZAP."
            )

    request = ZapAssessmentRequest(
        authorized_host="portal.example.com",
        web_inventory=_inventory(),
        policy_version="beacon-standard-v1",
        active_scan_enabled=True,
    )

    client = NoNetworkZapClient()

    import pytest

    with pytest.raises(
        ZapScannerError,
        match="resolved ZAP policy",
    ):
        client.run_assessment(
            request
        )

    assert client.calls == []


def test_zap_active_runner_composes_governed_workflow_in_order():
    from datetime import datetime, timezone

    from app.assessment.authorization import (
        ActiveAuthorizationConfirmation,
    )
    from app.assessment.zap_policy import (
        resolve_zap_policy,
    )
    from app.scanners.zap import (
        ZapAssessmentRequest,
        ZapClient,
    )

    policy = resolve_zap_policy(
        profile_name="standard",
        active_confirmation=(
            ActiveAuthorizationConfirmation(
                confirmed=True,
                confirmed_by_user_id=42,
                confirmed_at=datetime.now(
                    timezone.utc
                ),
                authorization_version="active-v1",
            )
        ),
    )

    class RecordingZapClient(ZapClient):
        def __init__(self):
            self.calls = []

        def wait_until_ready(self):
            self.calls.append(
                ("wait_until_ready",)
            )

            return "2.17.0"

        def start_new_session(
            self,
            session_name=None,
        ):
            self.calls.append(
                (
                    "start_new_session",
                    session_name,
                )
            )

        def access_target(
            self,
            target_url,
        ):
            self.calls.append(
                (
                    "access_target",
                    target_url,
                )
            )

        def start_spider(
            self,
            target_url,
        ):
            self.calls.append(
                (
                    "start_spider",
                    target_url,
                )
            )

            return "spider-7"

        def wait_for_spider(
            self,
            scan_id,
        ):
            self.calls.append(
                (
                    "wait_for_spider",
                    scan_id,
                )
            )

        def wait_for_passive_scan(self):
            self.calls.append(
                ("wait_for_passive_scan",)
            )

        def create_assessment_context(
            self,
            *,
            context_name,
            authorized_host,
            origins,
        ):
            self.calls.append(
                (
                    "create_assessment_context",
                    context_name,
                    authorized_host,
                    origins,
                )
            )

            return "17"

        def configure_active_scan_policy(
            self,
            *,
            scan_policy_name,
            policy,
        ):
            self.calls.append(
                (
                    "configure_active_scan_policy",
                    scan_policy_name,
                    policy.policy_version,
                )
            )

        def configure_active_scan_limits(
            self,
            *,
            policy,
        ):
            self.calls.append(
                (
                    "configure_active_scan_limits",
                    policy.policy_version,
                )
            )

        def start_active_scan(
            self,
            *,
            target_url,
            authorized_host,
            context_id,
            scan_policy_name,
            policy,
        ):
            self.calls.append(
                (
                    "start_active_scan",
                    target_url,
                    authorized_host,
                    context_id,
                    scan_policy_name,
                    policy.policy_version,
                )
            )

            return "91"

        def wait_for_active_scan(
            self,
            *,
            scan_id,
            timeout_seconds=None,
        ):
            self.calls.append(
                (
                    "wait_for_active_scan",
                    scan_id,
                )
            )

        def get_alerts(
            self,
            target_url,
        ):
            self.calls.append(
                (
                    "get_alerts",
                    target_url,
                )
            )

            return [
                {
                    "pluginId": "40018",
                    "alert": "SQL Injection",
                    "risk": "High",
                    "confidence": "Medium",
                    "url": (
                        "https://portal.example.com/"
                        "search?q=test"
                    ),
                    "cweid": "89",
                },
            ]

    request = ZapAssessmentRequest(
        authorized_host="portal.example.com",
        web_inventory=_inventory(),
        policy_version=policy.policy_version,
        active_scan_enabled=True,
        active_policy=policy,
        execution_id="assessment-exec-123",
    )

    client = RecordingZapClient()

    result = client.run_assessment(
        request
    )

    assert client.calls == [
        (
            "wait_until_ready",
        ),
        (
            "start_new_session",
            "beacon-assessment-exec-123",
        ),
        (
            "access_target",
            "https://portal.example.com/",
        ),
        (
            "start_spider",
            "https://portal.example.com/",
        ),
        (
            "wait_for_spider",
            "spider-7",
        ),
        (
            "wait_for_passive_scan",
        ),
        (
            "create_assessment_context",
            "beacon-assessment-exec-123",
            "portal.example.com",
            (
                "https://portal.example.com/",
            ),
        ),
        (
            "configure_active_scan_policy",
            (
                "beacon-assessment-exec-123-"
                "standard"
            ),
            "beacon-standard-v1",
        ),
        (
            "configure_active_scan_limits",
            "beacon-standard-v1",
        ),
        (
            "start_active_scan",
            "https://portal.example.com/",
            "portal.example.com",
            "17",
            (
                "beacon-assessment-exec-123-"
                "standard"
            ),
            "beacon-standard-v1",
        ),
        (
            "wait_for_active_scan",
            "91",
        ),
        (
            "wait_for_passive_scan",
        ),
        (
            "get_alerts",
            "https://portal.example.com/",
        ),
    ]

    assert result.version == "2.17.0"

    assert result.policy_version == (
        "beacon-standard-v1"
    )

    assert result.active_scan_enabled is True

    assert len(
        result.detections
    ) == 1

    assert result.detections[0].title == (
        "SQL Injection"
    )

    assert result.detections[0].severity == (
        "high"
    )


def test_zap_active_runner_requires_nonempty_execution_id_before_network():
    from datetime import datetime, timezone

    import pytest

    from app.assessment.authorization import (
        ActiveAuthorizationConfirmation,
    )
    from app.assessment.zap_policy import (
        resolve_zap_policy,
    )
    from app.scanners.zap import (
        ZapAssessmentRequest,
        ZapClient,
        ZapScannerError,
    )

    policy = resolve_zap_policy(
        profile_name="standard",
        active_confirmation=(
            ActiveAuthorizationConfirmation(
                confirmed=True,
                confirmed_by_user_id=42,
                confirmed_at=datetime.now(
                    timezone.utc
                ),
                authorization_version="active-v1",
            )
        ),
    )

    invalid_execution_ids = (
        None,
        "",
        "   ",
    )

    for execution_id in invalid_execution_ids:
        class NoNetworkZapClient(ZapClient):
            def __init__(self):
                self.calls = []

            def wait_until_ready(self):
                self.calls.append(
                    ("wait_until_ready",)
                )

                raise AssertionError(
                    "Execution ID validation "
                    "must happen before ZAP access."
                )

        request = ZapAssessmentRequest(
            authorized_host="portal.example.com",
            web_inventory=_inventory(),
            policy_version=policy.policy_version,
            active_scan_enabled=True,
            active_policy=policy,
            execution_id=execution_id,
        )

        client = NoNetworkZapClient()

        with pytest.raises(
            ZapScannerError,
            match="execution ID",
        ):
            client.run_assessment(
                request
            )

        assert client.calls == []


def test_zap_new_session_accepts_execution_specific_name():
    from app.scanners.zap import (
        ZapClient,
    )

    class RecordingZapClient(ZapClient):
        def __init__(self):
            self.calls = []

        def _request(
            self,
            path,
            parameters=None,
        ):
            parameters = dict(
                parameters or {}
            )

            self.calls.append(
                (
                    path,
                    parameters,
                )
            )

            return {}

    client = RecordingZapClient()

    client.start_new_session(
        session_name="beacon-assessment-exec-123",
    )

    assert client.calls == [
        (
            "/JSON/core/action/newSession/",
            {
                "name": (
                    "beacon-assessment-exec-123"
                ),
                "overwrite": "true",
            },
        ),
    ]
