from types import MappingProxyType
from typing import Mapping, cast

from app.assessment.types import (
    AssessmentProfile,
    AssessmentProfileName,
    EnginePolicy,
)


def _engine_policies(
    values: Mapping[str, EnginePolicy],
) -> Mapping[str, EnginePolicy]:
    return MappingProxyType(dict(values))


_PROFILES: Mapping[str, AssessmentProfile] = MappingProxyType(
    {
        "quick": AssessmentProfile(
            name="quick",
            version="quick-v1",
            active_web_testing=False,
            infrastructure_extension_allowed=False,
            infrastructure_extension_default=False,
            target_request_rate=5,
            total_timeout_seconds=15 * 60,
            engines=_engine_policies(
                {
                    "nmap": EnginePolicy(
                        enabled=True,
                        timeout_seconds=120,
                    ),
                    "httpx": EnginePolicy(
                        enabled=True,
                        timeout_seconds=120,
                    ),
                    "katana": EnginePolicy(
                        enabled=True,
                        timeout_seconds=300,
                    ),
                    "sslyze": EnginePolicy(
                        enabled=True,
                        timeout_seconds=300,
                    ),
                    "nuclei": EnginePolicy(
                        enabled=True,
                        timeout_seconds=600,
                    ),
                    "zap": EnginePolicy(
                        enabled=True,
                        active=False,
                        timeout_seconds=600,
                    ),
                    "nikto": EnginePolicy(
                        enabled=False,
                        timeout_seconds=0,
                        required=False,
                    ),
                }
            ),
        ),
        "standard": AssessmentProfile(
            name="standard",
            version="standard-v1",
            active_web_testing=True,
            infrastructure_extension_allowed=False,
            infrastructure_extension_default=False,
            target_request_rate=10,
            total_timeout_seconds=60 * 60,
            engines=_engine_policies(
                {
                    "nmap": EnginePolicy(
                        enabled=True,
                        timeout_seconds=600,
                    ),
                    "httpx": EnginePolicy(
                        enabled=True,
                        timeout_seconds=300,
                    ),
                    "katana": EnginePolicy(
                        enabled=True,
                        timeout_seconds=900,
                    ),
                    "sslyze": EnginePolicy(
                        enabled=True,
                        timeout_seconds=600,
                    ),
                    "nuclei": EnginePolicy(
                        enabled=True,
                        timeout_seconds=1800,
                    ),
                    "zap": EnginePolicy(
                        enabled=True,
                        active=True,
                        timeout_seconds=1800,
                    ),
                    "nikto": EnginePolicy(
                        enabled=True,
                        timeout_seconds=600,
                        required=False,
                    ),
                }
            ),
        ),
        "deep": AssessmentProfile(
            name="deep",
            version="deep-v1",
            active_web_testing=True,
            infrastructure_extension_allowed=True,
            infrastructure_extension_default=False,
            target_request_rate=20,
            total_timeout_seconds=180 * 60,
            engines=_engine_policies(
                {
                    "nmap": EnginePolicy(
                        enabled=True,
                        timeout_seconds=1800,
                    ),
                    "httpx": EnginePolicy(
                        enabled=True,
                        timeout_seconds=600,
                    ),
                    "katana": EnginePolicy(
                        enabled=True,
                        timeout_seconds=1800,
                    ),
                    "sslyze": EnginePolicy(
                        enabled=True,
                        timeout_seconds=900,
                    ),
                    "nuclei": EnginePolicy(
                        enabled=True,
                        timeout_seconds=3600,
                    ),
                    "zap": EnginePolicy(
                        enabled=True,
                        active=True,
                        timeout_seconds=3600,
                    ),
                    "nikto": EnginePolicy(
                        enabled=True,
                        timeout_seconds=900,
                        required=False,
                    ),
                }
            ),
        ),
    }
)


def get_assessment_profile(
    name: str,
) -> AssessmentProfile:
    try:
        return _PROFILES[name]
    except KeyError as exc:
        raise ValueError(
            f"Unknown assessment profile: {name}"
        ) from exc


def profile_requires_active_authorization(
    name: str,
) -> bool:
    return get_assessment_profile(name).active_web_testing


def assessment_profile_names() -> tuple[AssessmentProfileName, ...]:
    return cast(
        tuple[AssessmentProfileName, ...],
        tuple(_PROFILES),
    )
