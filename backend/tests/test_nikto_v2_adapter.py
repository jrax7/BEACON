from app.assessment.handoff import (
    HTTPService,
    HTTPServiceInventory,
)
from app.scanners import nikto


def test_quick_nikto_assessment_is_disabled_without_scanner_execution(
    monkeypatch,
):
    inventory = HTTPServiceInventory(
        services=(
            HTTPService(
                url="https://example.com/",
                host="example.com",
                port=443,
                scheme="https",
                status_code=200,
            ),
        )
    )

    scanner_calls: list[str] = []

    def forbidden_run_nikto_scan(
        target_url,
        progress_callback=None,
    ):
        scanner_calls.append(target_url)
        raise AssertionError(
            "Quick must not invoke the Nikto scanner."
        )

    monkeypatch.setattr(
        nikto,
        "run_nikto_scan",
        forbidden_run_nikto_scan,
    )

    run_assessment = getattr(
        nikto,
        "run_nikto_assessment",
        None,
    )

    assert callable(run_assessment), (
        "Engine v2 Nikto assessment runner does not exist yet."
    )

    result = run_assessment(
        profile_name="quick",
        inventory=inventory,
    )

    assert scanner_calls == []
    assert result.scan_results == ()
    assert result.detection_candidates == ()



def test_nikto_assessment_scans_only_urls_from_http_service_inventory(
    monkeypatch,
):
    inventory = HTTPServiceInventory(
        services=(
            HTTPService(
                url="https://example.com/",
                host="example.com",
                port=443,
                scheme="https",
                status_code=302,
                effective_url="https://outside.example.net/login",
                redirect_chain=(
                    "https://example.com/",
                    "https://outside.example.net/login",
                ),
            ),
            HTTPService(
                url="http://example.com:8080/",
                host="example.com",
                port=8080,
                scheme="http",
                status_code=200,
            ),
        )
    )

    scanner_calls: list[str] = []

    def fake_run_nikto_scan(
        target_url,
        progress_callback=None,
    ):
        scanner_calls.append(
            target_url
        )

        return nikto.NiktoScanResult(
            scanner_version="2.6.0",
            command_summary="test",
            target_url=target_url,
            host="example.com",
            ip_address="203.0.113.10",
            port=443,
            server_banner=None,
            start_time=None,
            end_time=None,
            raw_json=b"[]",
            console_output="",
            reached_max_time=False,
            soft_404_detected=False,
            completed_requests=1,
            request_error_count=0,
            findings=[],
        )

    monkeypatch.setattr(
        nikto,
        "run_nikto_scan",
        fake_run_nikto_scan,
    )

    result = nikto.run_nikto_assessment(
        profile_name="standard",
        inventory=inventory,
    )

    assert scanner_calls == [
        "https://example.com/",
        "http://example.com:8080/",
    ]

    assert [
        scan.target_url
        for scan in result.scan_results
    ] == scanner_calls

    assert result.detection_candidates == ()



def test_nikto_result_is_converted_to_detection_candidate(
    monkeypatch,
):
    inventory = HTTPServiceInventory(
        services=(
            HTTPService(
                url="https://example.com/",
                host="example.com",
                port=443,
                scheme="https",
                status_code=200,
            ),
        )
    )

    def fake_run_nikto_scan(
        target_url,
        progress_callback=None,
    ):
        return nikto.NiktoScanResult(
            scanner_version="2.6.0",
            command_summary="test-profile",
            target_url=target_url,
            host="example.com",
            ip_address="203.0.113.10",
            port=443,
            server_banner="nginx",
            start_time="2026-08-29 10:00:00",
            end_time="2026-08-29 10:00:10",
            raw_json=b'{"raw":"nikto"}',
            console_output="1 requests: 0 errors and 1 items reported",
            reached_max_time=False,
            soft_404_detected=False,
            completed_requests=1,
            request_error_count=0,
            findings=[
                nikto.NiktoFindingResult(
                    finding_id="999001",
                    method="get",
                    path="/admin",
                    message=(
                        "Suggested security header missing: "
                        "X-Frame-Options"
                    ),
                    references=[
                        "https://example.test/reference",
                    ],
                ),
            ],
        )

    monkeypatch.setattr(
        nikto,
        "run_nikto_scan",
        fake_run_nikto_scan,
    )

    result = nikto.run_nikto_assessment(
        profile_name="standard",
        inventory=inventory,
    )

    assert len(
        result.detection_candidates
    ) == 1

    candidate = result.detection_candidates[
        0
    ]

    assert isinstance(
        candidate,
        nikto.NiktoDetectionCandidate,
    )

    assert candidate.finding_id == "999001"

    assert candidate.title == (
        "Suggested security header missing: "
        "X-Frame-Options"
    )

    assert candidate.severity == "low"
    assert candidate.confidence == "medium"

    assert candidate.affected_url == (
        "https://example.com/admin"
    )

    assert candidate.affected_port == 443
    assert candidate.method == "GET"

    assert candidate.references == (
        "https://example.test/reference",
    )

    assert candidate.evidence[
        "nikto_id"
    ] == "999001"

    assert candidate.evidence[
        "reported_path"
    ] == "/admin"

    assert candidate.evidence[
        "soft_404_detected"
    ] is False

    assert not hasattr(
        candidate,
        "scan_id",
    )

    assert not hasattr(
        candidate,
        "tool_run_id",
    )



def test_nikto_candidate_cannot_escape_original_service_origin(
    monkeypatch,
):
    inventory = HTTPServiceInventory(
        services=(
            HTTPService(
                url="https://portal.example.com/",
                host="portal.example.com",
                port=443,
                scheme="https",
                status_code=200,
            ),
        )
    )

    def fake_run_nikto_scan(
        target_url,
        progress_callback=None,
    ):
        return nikto.NiktoScanResult(
            scanner_version="2.6.0",
            command_summary="test",
            target_url=target_url,
            host="portal.example.com",
            ip_address="203.0.113.10",
            port=443,
            server_banner=None,
            start_time=None,
            end_time=None,
            raw_json=b"[]",
            console_output="",
            reached_max_time=False,
            soft_404_detected=False,
            completed_requests=1,
            request_error_count=0,
            findings=[
                nikto.NiktoFindingResult(
                    finding_id="escape",
                    method="GET",
                    path=(
                        "https://evil.example.net/"
                        "not-authorized"
                    ),
                    message=(
                        "External path-shaped observation"
                    ),
                    references=[],
                ),
            ],
        )

    monkeypatch.setattr(
        nikto,
        "run_nikto_scan",
        fake_run_nikto_scan,
    )

    result = nikto.run_nikto_assessment(
        profile_name="standard",
        inventory=inventory,
    )

    candidate = result.detection_candidates[
        0
    ]

    assert candidate.affected_url == (
        "https://portal.example.com/"
    )

    assert candidate.evidence[
        "reported_path"
    ] == (
        "https://evil.example.net/"
        "not-authorized"
    )



def test_nikto_assessment_preserves_raw_scanner_evidence(
    monkeypatch,
):
    inventory = HTTPServiceInventory(
        services=(
            HTTPService(
                url="https://example.com/",
                host="example.com",
                port=443,
                scheme="https",
                status_code=200,
            ),
            HTTPService(
                url="http://example.com:8080/",
                host="example.com",
                port=8080,
                scheme="http",
                status_code=200,
            ),
        )
    )

    payloads = {
        "https://example.com/":
            b'{"service":"https"}',
        "http://example.com:8080/":
            b'{"service":"http"}',
    }

    def fake_run_nikto_scan(
        target_url,
        progress_callback=None,
    ):
        return nikto.NiktoScanResult(
            scanner_version="2.6.0",
            command_summary="test",
            target_url=target_url,
            host="example.com",
            ip_address="203.0.113.10",
            port=(
                443
                if target_url.startswith(
                    "https://"
                )
                else 8080
            ),
            server_banner=None,
            start_time=None,
            end_time=None,
            raw_json=payloads[
                target_url
            ],
            console_output="",
            reached_max_time=False,
            soft_404_detected=False,
            completed_requests=1,
            request_error_count=0,
            findings=[],
        )

    monkeypatch.setattr(
        nikto,
        "run_nikto_scan",
        fake_run_nikto_scan,
    )

    result = nikto.run_nikto_assessment(
        profile_name="standard",
        inventory=inventory,
    )

    assert result.raw_evidence == (
        b'{"service":"https"}',
        b'{"service":"http"}',
    )



def test_nikto_soft_404_path_detection_reduces_candidate_confidence(
    monkeypatch,
):
    inventory = HTTPServiceInventory(
        services=(
            HTTPService(
                url="https://example.com/",
                host="example.com",
                port=443,
                scheme="https",
                status_code=200,
            ),
        )
    )

    def fake_run_nikto_scan(
        target_url,
        progress_callback=None,
    ):
        return nikto.NiktoScanResult(
            scanner_version="2.6.0",
            command_summary="test",
            target_url=target_url,
            host="example.com",
            ip_address="203.0.113.10",
            port=443,
            server_banner=None,
            start_time=None,
            end_time=None,
            raw_json=b"[]",
            console_output="",
            reached_max_time=False,
            soft_404_detected=True,
            completed_requests=1,
            request_error_count=0,
            findings=[
                nikto.NiktoFindingResult(
                    finding_id="soft404",
                    method="GET",
                    path="/admin",
                    message=(
                        "This might be interesting"
                    ),
                    references=[],
                ),
            ],
        )

    monkeypatch.setattr(
        nikto,
        "run_nikto_scan",
        fake_run_nikto_scan,
    )

    result = nikto.run_nikto_assessment(
        profile_name="standard",
        inventory=inventory,
    )

    candidate = result.detection_candidates[
        0
    ]

    assert candidate.confidence == "low"

    assert candidate.evidence[
        "soft_404_detected"
    ] is True


# TASK27_LIVE_CANCEL_RED_BEGIN
def test_nikto_running_process_terminates_when_cancellation_is_requested(
    monkeypatch,
):
    """A running Nikto child must stop cooperatively on assessment cancel."""

    from types import SimpleNamespace

    import pytest

    from app.scanners import nikto


    calls = []


    class Process:
        def __init__(self):
            self.stdout = SimpleNamespace(
                fileno=lambda: 0,
            )

            self.terminated = False
            self.killed = False

        def poll(self):
            if self.terminated:
                return -15

            if self.killed:
                return -9

            return None

        def terminate(self):
            calls.append(
                "terminate"
            )

            self.terminated = True

        def kill(self):
            calls.append(
                "kill"
            )

            self.killed = True

        def wait(
            self,
            timeout=None,
        ):
            calls.append(
                (
                    "wait",
                    timeout,
                )
            )

            if self.killed:
                return -9

            if self.terminated:
                return -15

            return 0


    class Selector:
        def register(
            self,
            fileobj,
            events,
        ):
            calls.append(
                "register"
            )

        def select(
            self,
            timeout=None,
        ):
            calls.append(
                "select"
            )

            return []

        def close(self):
            calls.append(
                "close"
            )


    process = Process()


    monkeypatch.setattr(
        nikto,
        "validate_nikto_target_url",
        lambda target_url:
            target_url,
    )

    monkeypatch.setattr(
        nikto,
        "configured_nikto_tuning",
        lambda:
            "23b",
    )

    monkeypatch.setattr(
        nikto,
        "get_nikto_version",
        lambda:
            "Nikto 2.6.0",
    )

    monkeypatch.setattr(
        nikto,
        "detect_soft_404",
        lambda target_url:
            False,
    )

    monkeypatch.setattr(
        nikto.subprocess,
        "Popen",
        lambda *args, **kwargs:
            process,
    )

    monkeypatch.setattr(
        nikto.selectors,
        "DefaultSelector",
        Selector,
    )


    cancellation_checks = []


    def cancellation_callback():
        cancellation_checks.append(
            True
        )

        return True


    with pytest.raises(
        nikto.NiktoScannerError,
        match="cancel",
    ):
        nikto.run_nikto_scan(
            "http://example.com/",
            cancellation_callback=(
                cancellation_callback
            ),
        )


    assert cancellation_checks

    assert process.terminated is True

    assert "terminate" in calls

    assert process.killed is False
# TASK27_LIVE_CANCEL_RED_END


# TASK27_LIVE_CANCEL_BRIDGE_RED_BEGIN
def test_nikto_assessment_forwards_cancellation_callback(
    monkeypatch,
):
    """The Engine-v2 Nikto adapter must propagate scanner cancellation."""

    from app.assessment.handoff import (
        HTTPService,
        HTTPServiceInventory,
    )
    from app.scanners import nikto


    cancellation_callback = (
        lambda:
            False
    )

    captured = []


    def fake_run_nikto_scan(
        target_url,
        progress_callback=None,
        cancellation_callback=None,
    ):
        captured.append(
            cancellation_callback
        )

        return nikto.NiktoScanResult(
            scanner_version="Nikto 2.6.0",
            command_summary="test",
            target_url=target_url,
            host="portal.example.com",
            ip_address="203.0.113.10",
            port=443,
            server_banner=None,
            start_time=None,
            end_time=None,
            raw_json=b"{}",
            console_output="",
            reached_max_time=False,
            soft_404_detected=False,
            completed_requests=0,
            request_error_count=0,
            findings=(),
        )


    monkeypatch.setattr(
        nikto,
        "run_nikto_scan",
        fake_run_nikto_scan,
    )


    result = (
        nikto.run_nikto_assessment(
            profile_name="standard",
            inventory=(
                HTTPServiceInventory(
                    services=(
                        HTTPService(
                            url=(
                                "https://"
                                "portal.example.com/"
                            ),
                            host=(
                                "portal.example.com"
                            ),
                            port=443,
                            scheme="https",
                        ),
                    )
                )
            ),
            cancellation_callback=(
                cancellation_callback
            ),
        )
    )


    assert len(
        result.scan_results
    ) == 1

    assert captured == [
        cancellation_callback,
    ]
# TASK27_LIVE_CANCEL_BRIDGE_RED_END
