from dataclasses import dataclass
from typing import Literal, Mapping


AssessmentProfileName = Literal[
    "quick",
    "standard",
    "deep",
]

AssessmentMode = Literal[
    "web",
    "api",
]


@dataclass(frozen=True)
class EnginePolicy:
    enabled: bool
    active: bool = False
    timeout_seconds: int = 0
    required: bool = True


@dataclass(frozen=True)
class AssessmentProfile:
    name: AssessmentProfileName
    version: str

    active_web_testing: bool

    infrastructure_extension_allowed: bool
    infrastructure_extension_default: bool

    target_request_rate: int
    total_timeout_seconds: int

    engines: Mapping[str, EnginePolicy]
