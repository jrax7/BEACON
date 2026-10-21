from dataclasses import dataclass
from urllib.parse import urlsplit

from app.assessment.authorization import (
    ActiveAuthorizationConfirmation,
    validate_active_authorization,
)
from app.assessment.handoff import (
    WebEndpoint,
    WebEndpointInventory,
)
from app.assessment.scope import (
    host_is_within_exact_fqdn,
)


@dataclass(frozen=True)
class ZapActiveRulePolicy:
    """One explicitly approved ZAP active scanner rule."""

    rule_id: int
    alert_threshold: str
    attack_strength: str


@dataclass(frozen=True)
class ZapPolicy:
    """One immutable BEACON ZAP execution policy."""

    profile_name: str
    policy_version: str
    active_scan_enabled: bool

    default_alert_threshold: str
    default_attack_strength: str

    active_rules: tuple[
        ZapActiveRulePolicy,
        ...
    ]

    max_rule_duration_minutes: int
    max_scan_duration_minutes: int
    max_alerts_per_rule: int


@dataclass(frozen=True)
class ZapScopeSelection:
    """Authorized and excluded web endpoints for one ZAP context."""

    authorized_host: str
    included_endpoints: tuple[WebEndpoint, ...]
    excluded_endpoints: tuple[WebEndpoint, ...]


def _rule(
    rule_id: int,
    *,
    attack_strength: str,
) -> ZapActiveRulePolicy:
    return ZapActiveRulePolicy(
        rule_id=rule_id,
        alert_threshold="MEDIUM",
        attack_strength=attack_strength,
    )


_STANDARD_ACTIVE_RULE_IDS = (
    6,       # Path Traversal
    20019,   # External Redirect
    40003,   # CRLF Injection
    40008,   # Parameter Tampering
    40012,   # Reflected XSS
    40018,   # SQL Injection
    40032,   # .htaccess Information Leak
    40034,   # .env Information Leak
    40035,   # Hidden File Finder
    90021,   # XPath Injection
)


_DEEP_ACTIVE_RULE_IDS = (
    6,       # Path Traversal
    7,       # Remote File Inclusion
    20019,   # External Redirect
    40003,   # CRLF Injection
    40008,   # Parameter Tampering
    40009,   # Server Side Include
    40012,   # Reflected XSS
    40018,   # SQL Injection
    40032,   # .htaccess Information Leak
    40034,   # .env Information Leak
    40035,   # Hidden File Finder
    40042,   # Spring Actuator Information Leak
    90017,   # XSLT Injection
    90019,   # Server Side Code Injection
    90020,   # Remote OS Command Injection
    90021,   # XPath Injection
    90023,   # XML External Entity
    90035,   # Server Side Template Injection
)


def resolve_zap_policy(
    *,
    profile_name: str,
    active_confirmation: ActiveAuthorizationConfirmation | None,
) -> ZapPolicy:
    """Resolve the governed ZAP policy for one assessment profile."""

    if profile_name == "quick":
        return ZapPolicy(
            profile_name="quick",
            policy_version="beacon-quick-v1",
            active_scan_enabled=False,
            default_alert_threshold="OFF",
            default_attack_strength="LOW",
            active_rules=(),
            max_rule_duration_minutes=0,
            max_scan_duration_minutes=0,
            max_alerts_per_rule=0,
        )

    if profile_name not in {
        "standard",
        "deep",
    }:
        raise ValueError(
            f"Unsupported ZAP assessment profile: {profile_name!r}."
        )

    validate_active_authorization(
        profile_name=profile_name,
        confirmation=active_confirmation,
    )

    if profile_name == "standard":
        attack_strength = "LOW"

        active_rules = tuple(
            _rule(
                rule_id,
                attack_strength=attack_strength,
            )
            for rule_id in _STANDARD_ACTIVE_RULE_IDS
        )

        return ZapPolicy(
            profile_name="standard",
            policy_version="beacon-standard-v1",
            active_scan_enabled=True,
            default_alert_threshold="OFF",
            default_attack_strength=attack_strength,
            active_rules=active_rules,
            max_rule_duration_minutes=2,
            max_scan_duration_minutes=20,
            max_alerts_per_rule=20,
        )

    attack_strength = "MEDIUM"

    active_rules = tuple(
        _rule(
            rule_id,
            attack_strength=attack_strength,
        )
        for rule_id in _DEEP_ACTIVE_RULE_IDS
    )

    return ZapPolicy(
        profile_name="deep",
        policy_version="beacon-deep-v1",
        active_scan_enabled=True,
        default_alert_threshold="OFF",
        default_attack_strength=attack_strength,
        active_rules=active_rules,
        max_rule_duration_minutes=5,
        max_scan_duration_minutes=45,
        max_alerts_per_rule=50,
    )


def build_zap_scope_selection(
    *,
    authorized_host: str,
    inventory: WebEndpointInventory,
) -> ZapScopeSelection:
    """Select only exact-FQDN HTTP endpoints for ZAP scope."""

    included: list[WebEndpoint] = []
    excluded: list[WebEndpoint] = []

    for endpoint in inventory.endpoints:
        parsed = urlsplit(
            endpoint.url
        )

        if (
            parsed.scheme.lower() in {
                "http",
                "https",
            }
            and parsed.hostname is not None
            and parsed.username is None
            and parsed.password is None
            and host_is_within_exact_fqdn(
                parsed.hostname,
                authorized_host,
            )
        ):
            included.append(
                endpoint
            )
        else:
            excluded.append(
                endpoint
            )

    return ZapScopeSelection(
        authorized_host=authorized_host,
        included_endpoints=tuple(
            included
        ),
        excluded_endpoints=tuple(
            excluded
        ),
    )
