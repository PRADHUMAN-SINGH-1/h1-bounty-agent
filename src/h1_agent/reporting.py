from __future__ import annotations

from .models import Finding


def markdown_report(finding: Finding) -> str:
    evidence = "\n".join(
        f"- {e.name}: {e.value} (source: {e.source})"
        for e in finding.evidence
    )
    reproduction = "\n".join(
        f"{i+1}. {step}" for i, step in enumerate(finding.reproduction)
    )
    return f"""# {finding.title}

## Summary
{finding.summary}

## Impact
{finding.impact}

## Steps to Reproduce
{reproduction}

## Evidence
{evidence or '- None'}

## Severity
{finding.severity or 'REVIEW REQUIRED'}

## Program / Asset
- Program: {finding.program_handle}
- Target: {finding.target}

## Researcher validation
Before submission, personally reproduce the behavior, confirm scope and program rules, verify all evidence, check for duplicates/exclusions, and confirm severity.
"""
