import importlib.util


def _profiles_module():
    spec = importlib.util.find_spec("app.assessment.profiles")
    assert spec is not None, (
        "Engine v2 assessment profiles module does not exist yet"
    )

    from app.assessment import profiles

    return profiles


def test_quick_is_passive_and_nikto_is_disabled():
    profiles = _profiles_module()

    profile = profiles.get_assessment_profile("quick")

    assert profile.name == "quick"
    assert profile.version == "quick-v1"
    assert profile.active_web_testing is False
    assert profile.infrastructure_extension_allowed is False
    assert profile.infrastructure_extension_default is False

    assert profile.engines["zap"].enabled is True
    assert profile.engines["zap"].active is False

    assert profile.engines["nikto"].enabled is False
    assert profile.engines["nikto"].required is False


def test_standard_is_the_main_active_web_profile():
    profiles = _profiles_module()

    profile = profiles.get_assessment_profile("standard")

    assert profile.name == "standard"
    assert profile.version == "standard-v1"
    assert profile.active_web_testing is True

    assert profile.infrastructure_extension_allowed is False
    assert profile.infrastructure_extension_default is False

    for engine in (
        "nmap",
        "httpx",
        "katana",
        "sslyze",
        "nuclei",
        "zap",
        "nikto",
    ):
        assert profile.engines[engine].enabled is True

    assert profile.engines["zap"].active is True
    assert profile.engines["nikto"].required is False


def test_deep_allows_but_does_not_default_infrastructure_extension():
    profiles = _profiles_module()

    profile = profiles.get_assessment_profile("deep")

    assert profile.name == "deep"
    assert profile.version == "deep-v1"
    assert profile.active_web_testing is True
    assert profile.infrastructure_extension_allowed is True
    assert profile.infrastructure_extension_default is False
    assert profile.engines["zap"].active is True


def test_profile_traffic_and_time_budgets_increase_by_depth():
    profiles = _profiles_module()

    quick = profiles.get_assessment_profile("quick")
    standard = profiles.get_assessment_profile("standard")
    deep = profiles.get_assessment_profile("deep")

    assert (
        quick.target_request_rate
        < standard.target_request_rate
        < deep.target_request_rate
    )

    assert (
        quick.total_timeout_seconds
        < standard.total_timeout_seconds
        < deep.total_timeout_seconds
    )


def test_unknown_profile_is_rejected():
    profiles = _profiles_module()

    try:
        profiles.get_assessment_profile("insane")
    except ValueError as exc:
        assert "Unknown assessment profile" in str(exc)
    else:
        raise AssertionError("unknown assessment profile was accepted")


def test_only_standard_and_deep_require_active_authorization():
    profiles = _profiles_module()

    assert (
        profiles.profile_requires_active_authorization("quick")
        is False
    )
    assert (
        profiles.profile_requires_active_authorization("standard")
        is True
    )
    assert (
        profiles.profile_requires_active_authorization("deep")
        is True
    )


def test_returned_profile_engine_mapping_cannot_be_mutated():
    profiles = _profiles_module()

    profile = profiles.get_assessment_profile("standard")

    try:
        profile.engines["zap"] = profile.engines["nmap"]
    except TypeError:
        pass
    else:
        raise AssertionError(
            "assessment profile engine policy mapping is mutable"
        )
