from h1_agent.models import Evidence, Finding
from h1_agent.reporting import markdown_report


def test_report_contains_triage_critical_sections():
    finding = Finding(
        program_handle="cloudflare",
        target="https://example.com/api",
        title="Example security issue",
        severity="high",
        state="needs_review",
        summary="Summary",
        impact="Impact",
        reproduction=["Step one", "Step two"],
        evidence=[Evidence("status", "200", "https://example.com/api")],
        structured_scope_id="123",
        weakness_id=1,
        metadata={
            "asset_type": "URL",
            "asset_identifier": "example.com/api",
            "scope_reference": "H001",
            "scope_max_severity": "critical",
            "affected_component": "API endpoint",
            "preconditions": "Authenticated account",
            "observed_behavior": "Observed",
            "expected_behavior": "Expected",
            "attack_scenario": "Scenario",
            "remediation": "Fix",
            "references": ["https://example.com/reference"],
            "cvss_score": 8.1,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        },
    )
    text = markdown_report(finding)
    for heading in (
        "Affected Asset",
        "Weakness and Severity",
        "Technical Description",
        "Preconditions",
        "Observed Behavior",
        "Expected Behavior",
        "Steps to Reproduce",
        "Security Impact",
        "Attack Scenario",
        "Evidence",
        "Supporting References",
        "Remediation / Mitigation",
        "Researcher Submission Checklist",
    ):
        assert heading in text
