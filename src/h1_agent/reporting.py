from __future__ import annotations

from .models import Finding


def _bullet(value: object) -> str:
    if value is None:
        return ""
    text = str(value).strip()
    return f"- {text}" if text else ""


def markdown_report(finding: Finding) -> str:
    metadata = finding.metadata or {}
    evidence = '\n'.join(
        f"- **{e.name}**: {e.value}  \n  Source: {e.source}  \n  Observed: {e.timestamp}"
        for e in finding.evidence
    )
    reproduction = '\n'.join(
        f"{i+1}. {step}" for i, step in enumerate(finding.reproduction)
    )

    references = metadata.get('references') or []
    if isinstance(references, str):
        references = [references]
    reference_text = '\n'.join(_bullet(ref) for ref in references if str(ref).strip()) or '- None provided'

    validation_notes = metadata.get('missing_validation') or []
    if isinstance(validation_notes, str):
        validation_notes = [validation_notes]
    validation_text = '\n'.join(_bullet(item) for item in validation_notes if str(item).strip()) or '- None'

    return f"""# {finding.title[:149]}

## Summary
{finding.summary}

## Affected Asset
- Program: {finding.program_handle}
- Asset / target: {finding.target}
- Structured scope ID: {finding.structured_scope_id or 'Not recorded'}
- Bounty eligibility: verified from the matched structured scope before approval

## Weakness and Severity
- Weakness / CWE: {metadata.get('weakness_name') or finding.weakness_id or 'Review required'}
- Severity: {finding.severity or 'REVIEW REQUIRED'}
- CVSS score: {metadata.get('cvss_score') or 'Review required'}
- CVSS vector: {metadata.get('cvss_vector') or 'Review required'}

## Technical Description
{metadata.get('affected_component') or 'Review required'}

### Preconditions
{metadata.get('preconditions') or 'Review required'}

### Observed Behavior
{metadata.get('observed_behavior') or 'Review required'}

### Expected Behavior
{metadata.get('expected_behavior') or 'Review required'}

## Steps to Reproduce
{reproduction or 'Review required'}

## Security Impact
{finding.impact}

### Attack Scenario
{metadata.get('attack_scenario') or 'Review required'}

## Evidence
{evidence or '- None'}

## Supporting References
{reference_text}

## Remediation / Mitigation
{metadata.get('remediation') or 'Program/security team to determine the appropriate remediation.'}

## Validation Notes
{validation_text}

## Researcher Submission Checklist
- Reproduced the behavior personally.
- Confirmed the exact asset remains eligible for submission and bounty.
- Reviewed the program's current policy, instructions, and exclusions.
- Verified every evidence item and sanitized sensitive data.
- Checked duplicates / known issues.
- Confirmed severity and weakness classification.
- Confirmed that reproduction is accurate and non-destructive.

This report is an evidence-grounded candidate. Human validation is required before submission.
"""
    