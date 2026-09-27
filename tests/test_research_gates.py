from h1_agent.research_gates import (
    CONFIRMED,
    DUPLICATE,
    OUT_OF_SCOPE,
    UNCONFIRMED,
    confirmation_gate,
    explicit_program_allowed,
)


def evidence_all():
    return [
        {"name": "reproduction_confirmed", "value": "true"},
        {"name": "security_boundary_crossed", "value": "true"},
        {"name": "impact_demonstrated", "value": "true"},
        {"name": "repeatable", "value": "true"},
    ]


def test_confirmation_requires_all_proof_dimensions():
    status, missing = confirmation_gate(
        evidence=evidence_all(), target_in_scope=True, duplicate_checked=True
    )
    assert status == CONFIRMED
    assert missing == []


def test_missing_impact_is_unconfirmed():
    evidence = [item for item in evidence_all() if item["name"] != "impact_demonstrated"]
    status, missing = confirmation_gate(
        evidence=evidence, target_in_scope=True, duplicate_checked=True
    )
    assert status == UNCONFIRMED
    assert "security impact was demonstrated with the minimum safe proof" in missing


def test_scope_failure_is_hard_block():
    status, missing = confirmation_gate(
        evidence=evidence_all(), target_in_scope=False, duplicate_checked=True
    )
    assert status == OUT_OF_SCOPE
    assert missing


def test_duplicate_failure_is_hard_block():
    status, missing = confirmation_gate(
        evidence=evidence_all(), target_in_scope=True, duplicate_checked=True, duplicate_match=True
    )
    assert status == DUPLICATE
    assert missing


def test_program_must_be_explicitly_authorized():
    assert explicit_program_allowed("superhuman", requested_programs={"superhuman"})
    assert not explicit_program_allowed("kong", requested_programs={"superhuman"})
    assert explicit_program_allowed("superhuman", allowlist=("superhuman",))
    assert not explicit_program_allowed("kong", allowlist=("superhuman",))
