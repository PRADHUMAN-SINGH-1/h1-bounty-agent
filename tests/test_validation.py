from h1_agent.models import Evidence, Finding
from h1_agent.validation import validate_finding


def confirmed_gate():
    return {
        "status": "CONFIRMED",
        "reproduced": True,
        "security_boundary_crossed": True,
        "impact_demonstrated": True,
        "repeatable": True,
        "target_in_scope": True,
        "duplicate_check_complete": True,
        "duplicate_match": False,
    }


def base_metadata():
    return {
        "affected_component": "Example endpoint",
        "preconditions": "Researcher-owned test account can reach the endpoint.",
        "observed_behavior": "Observed security-relevant behavior",
        "expected_behavior": "Authorization should prevent the observed behavior",
        "attack_scenario": "A researcher-controlled account crosses the demonstrated security boundary.",
        "remediation": "Enforce the expected authorization boundary.",
        "cvss_score": 6.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        "reproduction_gate": confirmed_gate(),
    }


def test_complete_finding_passes_only_when_confirmed():
    finding = Finding(
        "demo", "https://example.com", "Finding", "medium", "needs_review",
        "summary", "impact", ["step"], [Evidence("x", "y", "z")], "1", 1, base_metadata(),
    )
    assert validate_finding(finding).ok


def test_unconfirmed_finding_is_blocked():
    metadata = base_metadata()
    metadata["reproduction_gate"] = {"status": "UNCONFIRMED"}
    finding = Finding(
        "demo", "https://example.com", "Finding", "medium", "needs_review",
        "summary", "impact", ["step"], [Evidence("x", "y", "z")], "1", 1, metadata,
    )
    result = validate_finding(finding)
    assert not result.ok
    assert "finding is not CONFIRMED by the reproduction gate" in result.blockers


def test_missing_evidence_blocks():
    finding = Finding("demo", "https://example.com", "", None, "needs_review", "", "", [], [])
    result = validate_finding(finding)
    assert not result.ok
    assert "missing evidence" in result.blockers


def test_duplicate_blocks_submission():
    metadata = base_metadata()
    metadata["reproduction_gate"]["duplicate_match"] = True
    finding = Finding(
        "demo", "https://example.com", "Finding", "medium", "needs_review",
        "summary", "impact", ["step"], [Evidence("x", "y", "z")], "1", 1, metadata,
    )
    result = validate_finding(finding)
    assert not result.ok
    assert "duplicate match prevents submission" in result.blockers
