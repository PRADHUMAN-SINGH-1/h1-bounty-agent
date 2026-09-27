from __future__ import annotations

from dataclasses import dataclass

from .models import Finding
from .research_gates import CONFIRMED


VALID_SEVERITIES = {"none", "low", "medium", "high", "critical"}


@dataclass(frozen=True)
class ValidationResult:
    ok: bool
    blockers: list[str]


def _truthy_gate(metadata: dict, key: str) -> bool:
    value = metadata.get(key)
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() == "true"


def _validate_reproduction_gate(metadata: dict, blockers: list[str]) -> None:
    gate = metadata.get("reproduction_gate") or {}
    if not isinstance(gate, dict):
        blockers.append("missing structured reproduction gate")
        return
    if str(gate.get("status") or "").upper() != CONFIRMED:
        blockers.append("finding is not CONFIRMED by the reproduction gate")
    for key, label in (
        ("reproduced", "behavior was not reproduced"),
        ("security_boundary_crossed", "security boundary crossing was not demonstrated"),
        ("impact_demonstrated", "security impact was not demonstrated"),
        ("repeatable", "repeatability was not demonstrated"),
        ("target_in_scope", "target scope was not verified"),
        ("duplicate_check_complete", "duplicate screening was not completed"),
    ):
        if not _truthy_gate(gate, key):
            blockers.append(label)
    if gate.get("duplicate_match"):
        blockers.append("duplicate match prevents submission")


def validate_finding(finding: Finding) -> ValidationResult:
    blockers: list[str] = []
    metadata = finding.metadata or {}

    if not finding.title.strip():
        blockers.append('missing title')
    elif len(finding.title.strip()) > 149:
        blockers.append('title must be under 150 characters')

    if not finding.summary.strip():
        blockers.append('missing summary')
    if not finding.impact.strip():
        blockers.append('missing impact')
    if not finding.reproduction:
        blockers.append('missing reproduction steps')
    if not finding.evidence:
        blockers.append('missing evidence')
    if not finding.target.strip():
        blockers.append('missing affected target')
    if finding.severity is None:
        blockers.append('severity must be selected before submission')
    elif finding.severity not in VALID_SEVERITIES:
        blockers.append(f'invalid severity: {finding.severity}')
    if not finding.structured_scope_id:
        blockers.append('missing structured scope ID')

    if metadata.get('missing_validation'):
        blockers.append('unresolved validation requirements')
    if not str(metadata.get('preconditions') or '').strip():
        blockers.append('missing preconditions')
    if not str(metadata.get('attack_scenario') or '').strip():
        blockers.append('missing attack scenario')
    if not str(metadata.get('remediation') or '').strip():
        blockers.append('missing remediation')
    if finding.weakness_id is None:
        blockers.append('missing weakness/CWE classification')
    if metadata.get('cvss_score') in (None, ''):
        blockers.append('missing CVSS score')
    if not str(metadata.get('cvss_vector') or '').strip():
        blockers.append('missing CVSS vector')

    for key in ('observed_behavior', 'expected_behavior', 'affected_component'):
        if not str(metadata.get(key) or '').strip():
            blockers.append(f'missing {key}')

    _validate_reproduction_gate(metadata, blockers)

    if finding.state not in {'draft', 'needs_review', 'approved'}:
        blockers.append(f'invalid state: {finding.state}')

    return ValidationResult(not blockers, blockers)


def require_human_approval(finding: Finding) -> None:
    result = validate_finding(finding)
    if not result.ok:
        raise ValueError('Finding is incomplete: ' + '; '.join(result.blockers))
    if finding.state != 'approved':
        raise PermissionError('Submission blocked: explicit human approval is required')