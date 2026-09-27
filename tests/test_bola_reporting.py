from h1_agent.models import Evidence
from h1_agent.worker import _idor_rule_based_candidate


class Asset:
    asset_type = "DOMAIN"
    asset_identifier = "example.com"
    reference = "https://hackerone.com/example"
    max_severity = "high"


def test_idor_rule_based_candidate_is_complete():
    target = "https://example.com/api/documents/123"
    evidence = [
        Evidence("idor_original_url", target, target),
        Evidence("idor_candidate_url", target, target),
        Evidence("idor_status_a", "200", target),
        Evidence("idor_status_b", "200", target),
        Evidence("idor_object_id", "123", target),
        Evidence("idor_owner_binding_a", "ownerId=A-OWNER-42", target),
        Evidence("idor_owner_binding_b", "ownerId=A-OWNER-42", target),
        Evidence("idor_fingerprint_a", "aaa", target),
        Evidence("idor_fingerprint_b", "aaa", target),
        Evidence("idor_same_object_access", "true", target),
        Evidence("idor_ownership_binding", "true", target),
        Evidence("idor_suspicious", "true", target),
        Evidence("idor_observation", "same object and owner binding", target),
    ]
    context = {
        "duplicate_screening": {
            "status": "checked",
            "disclosed_reports": [],
        }
    }

    candidate = _idor_rule_based_candidate(
        "example",
        target,
        Asset(),
        evidence,
        context,
    )

    assert candidate is not None
    assert candidate["status"] == "candidate"
    assert candidate["severity"] == "medium"
    assert candidate["weakness_id"] == 639
    assert candidate["metadata"]["cvss_score"] == 6.5
    assert candidate["metadata"]["cvss_vector"].startswith("CVSS:3.1/AV:N/AC:L/PR:L")
    assert len(candidate["evidence"]) >= 10
