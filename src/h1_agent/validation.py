from __future__ import annotations

from dataclasses import dataclass

@dataclass
class FindingDraft:
    title: str
    asset: str
    evidence: str
    impact: str
    reproduction: str
    confidence: float
    human_validated: bool = False

class HumanValidationGate:
    """A finding cannot become submission-ready until the operator validates it."""
    REQUIRED_CHECKS = (
        "reproduced_the_behavior",
        "confirmed_asset_is_in_scope",
        "confirmed_impact",
        "confirmed_evidence_is_accurate",
        "checked_program_specific_rules",
    )

    def validate(self, finding: FindingDraft, checks: set[str]) -> FindingDraft:
        missing = set(self.REQUIRED_CHECKS) - checks
        if missing:
            raise ValueError(f"Human validation incomplete: {', '.join(sorted(missing))}")
        finding.human_validated = True
        return finding

    def require_validated(self, finding: FindingDraft) -> None:
        if not finding.human_validated:
            raise PermissionError("Submission blocked: human validation is required")
