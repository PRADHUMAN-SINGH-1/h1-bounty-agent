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
        "1",
        1,
        {
            "affected_component": "Example endpoint",
            "preconditions": "Unauthenticated user can reach the endpoint.",
            "observed_behavior": "Observed",
            "expected_behavior": "Expected",
            "attack_scenario": "An attacker sends the documented request and obtains the demonstrated response.",
            "remediation": "Enforce the documented authorization boundary.",
            "cvss_score": 3.7,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        },
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


def test_complete_bounty_report_passes():
    from h1_agent.models import Evidence, Finding
    from h1_agent.validation import validate_finding
    finding = Finding(
        program_handle="example",
        target="https://example.com",
        title="Example security issue",
        severity="high",
        state="needs_review",
        summary="Summary",
        impact="Impact",
        reproduction=["Open the endpoint", "Observe the behavior"],
        evidence=[Evidence("status", "200", "https://example.com")],
        structured_scope_id="1",
        weakness_id=1,
        metadata={
            "affected_component": "Example endpoint",
            "preconditions": "Attacker can reach the endpoint.",
            "observed_behavior": "Observed behavior",
            "expected_behavior": "Expected behavior",
            "attack_scenario": "Attacker requests the endpoint and observes the demonstrated behavior.",
            "remediation": "Enforce the expected access control.",
            "cvss_score": 7.5,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        },
    )
    assert validate_finding(finding).ok
