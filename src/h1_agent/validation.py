from __future__ import annotations

from dataclasses import dataclass

from .models import Finding


@dataclass(frozen=True)
class ValidationResult:
    ok: bool
    blockers: list[str]


def validate_finding(finding: Finding) -> ValidationResult:
    blockers: list[str] = []
    if not finding.title.strip():
        blockers.append("missing title")
    if not finding.summary.strip():
        blockers.append("missing summary")
    if not finding.impact.strip():
        blockers.append("missing impact")
    if not finding.reproduction:
        blockers.append("missing reproduction steps")
    if not finding.evidence:
        blockers.append("missing evidence")
    if finding.state not in {"draft", "needs_review", "approved"}:
        blockers.append(f"invalid state: {finding.state}")
    return ValidationResult(not blockers, blockers)


def require_human_approval(finding: Finding) -> None:
    result = validate_finding(finding)
    if not result.ok:
        raise ValueError("Finding is incomplete: " + "; ".join(result.blockers))
    if finding.state != "approved":
        raise PermissionError("Submission blocked: explicit human approval is required")
