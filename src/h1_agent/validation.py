from __future__ import annotations

from dataclasses import dataclass

from .models import Finding


VALID_SEVERITIES = {"none", "low", "medium", "high", "critical"}


@dataclass(frozen=True)
class ValidationResult:
    ok: bool
    blockers: list[str]


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

    for key in ('observed_behavior', 'expected_behavior', 'affected_component'):
        if not str(metadata.get(key) or '').strip():
            blockers.append(f'missing {key}')

    if finding.state not in {'draft', 'needs_review', 'approved'}:
        blockers.append(f'invalid state: {finding.state}')

    return ValidationResult(not blockers, blockers)


def require_human_approval(finding: Finding) -> None:
    result = validate_finding(finding)
    if not result.ok:
        raise ValueError('Finding is incomplete: ' + '; '.join(result.blockers))
    if finding.state != 'approved':
        raise PermissionError('Submission blocked: explicit human approval is required')