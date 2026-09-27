from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json

CONFIRMED = "CONFIRMED"
UNCONFIRMED = "UNCONFIRMED"
FALSE_POSITIVE = "FALSE POSITIVE"
DUPLICATE = "DUPLICATE"
OUT_OF_SCOPE = "OUT OF SCOPE"
VALID_STATUSES = {CONFIRMED, UNCONFIRMED, FALSE_POSITIVE, DUPLICATE, OUT_OF_SCOPE}

CONFIRMATION_REQUIREMENTS = (
    ("reproduced", "the vulnerable behavior was actually reproduced"),
    ("security_boundary_crossed", "the relevant security boundary was demonstrated as crossed"),
    ("impact_demonstrated", "security impact was demonstrated with the minimum safe proof"),
    ("repeatable", "the result is repeatable"),
    ("target_in_scope", "the target is explicitly in scope"),
    ("duplicate_check_complete", "duplicate screening completed"),
)


@dataclass(frozen=True)
class ProgramAuthorization:
    handle: str
    policy_sha256: str
    scope_sha256: str
    exclusions_sha256: str
    weaknesses_sha256: str
    policy_present: bool
    exclusions_fetched: bool
    weaknesses_fetched: bool
    scope_count: int
    eligible_scope_count: int
    bounty_scope_count: int
    fetched_at: str

    def as_dict(self) -> dict:
        return asdict(self)


def stable_sha256(value: object) -> str:
    payload = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return sha256(payload.encode("utf-8")).hexdigest()


def build_program_authorization(
    handle: str,
    program_payload: dict,
    scopes_payload: dict,
    exclusions_payload: dict,
    weaknesses_payload: dict,
    scopes: list,
    fetched_at: str,
) -> ProgramAuthorization:
    attrs = (program_payload.get("data") or {}).get("attributes") or {}
    policy = str(attrs.get("policy") or attrs.get("description") or "").strip()
    if not policy:
        raise PermissionError(
            f"Blocked {handle}: current HackerOne program policy was not returned; "
            "research cannot start without the complete policy context."
        )
    return ProgramAuthorization(
        handle=handle,
        policy_sha256=stable_sha256(policy),
        scope_sha256=stable_sha256(scopes_payload),
        exclusions_sha256=stable_sha256(exclusions_payload),
        weaknesses_sha256=stable_sha256(weaknesses_payload),
        policy_present=True,
        exclusions_fetched=isinstance(exclusions_payload, dict),
        weaknesses_fetched=isinstance(weaknesses_payload, dict),
        scope_count=len(scopes),
        eligible_scope_count=sum(bool(item.eligible_for_submission) for item in scopes),
        bounty_scope_count=sum(bool(item.eligible_for_bounty and item.eligible_for_submission) for item in scopes),
        fetched_at=fetched_at,
    )


def explicit_program_allowed(handle: str, *, requested_programs=None, allowlist=()) -> bool:
    requested = {str(item).strip().lower() for item in (requested_programs or set()) if str(item).strip()}
    configured = {str(item).strip().lower() for item in allowlist if str(item).strip()}
    if requested:
        return handle.strip().lower() in requested
    return handle.strip().lower() in configured


def evidence_bool(evidence: list[dict], *names: str) -> bool:
    wanted = {name.lower() for name in names}
    return any(
        str(item.get("name") or "").lower() in wanted
        and str(item.get("value") or "").lower() == "true"
        for item in evidence
    )


def confirmation_gate(
    *, evidence: list[dict], target_in_scope: bool, duplicate_checked: bool, duplicate_match: bool = False
) -> tuple[str, list[str]]:
    if not target_in_scope:
        return OUT_OF_SCOPE, ["target failed the explicit scope gate"]
    if duplicate_match:
        return DUPLICATE, ["an existing matching disclosure was identified"]
    if not duplicate_checked:
        return UNCONFIRMED, ["duplicate screening is incomplete"]
    checks = {
        "reproduced": evidence_bool(
            evidence,
            "reproduction_confirmed",
            "vulnerability_reproduced",
            "xss_executed",
            "ssrf_callback_observed",
            "idor_same_object_access",
        ),
        "security_boundary_crossed": evidence_bool(
            evidence, "security_boundary_crossed", "idor_ownership_binding", "auth_boundary_crossed"
        ),
        "impact_demonstrated": evidence_bool(
            evidence,
            "impact_demonstrated",
            "sensitive_data_exposed",
            "ssrf_sensitive_boundary",
            "idor_same_object_access",
            "xss_executed",
        ),
        "repeatable": evidence_bool(evidence, "repeatable", "reproduction_repeatable"),
        "target_in_scope": True,
        "duplicate_check_complete": True,
    }
    missing = [description for key, description in CONFIRMATION_REQUIREMENTS if not checks[key]]
    if missing:
        return UNCONFIRMED, missing
    return CONFIRMED, []


def submission_status_allowed(status: str) -> bool:
    return str(status or "").upper().strip() == CONFIRMED
