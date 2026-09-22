from h1_agent.models import Evidence, Finding
from h1_agent.validation import validate_finding


def test_complete_finding_passes():
    finding = Finding(
        "demo",
        "https://example.com",
        "Finding",
        "low",
        "needs_review",
        "summary",
        "impact",
        ["step"],
        [Evidence("x", "y", "z")],
    )
    assert validate_finding(finding).ok


def test_missing_evidence_blocks():
    finding = Finding(
        "demo",
        "https://example.com",
        "",
        None,
        "needs_review",
        "",
        "",
        [],
        [],
    )
    result = validate_finding(finding)
    assert not result.ok
    assert "missing evidence" in result.blockers
