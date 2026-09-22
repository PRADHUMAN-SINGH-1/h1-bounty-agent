import pytest
from h1_agent.validation import FindingDraft, HumanValidationGate

def finding():
    return FindingDraft("test", "example.com", "evidence", "impact", "steps", 0.9)

def test_submission_requires_human_validation():
    gate = HumanValidationGate()
    with pytest.raises(PermissionError):
        gate.require_validated(finding())

def test_missing_checks_block_validation():
    gate = HumanValidationGate()
    with pytest.raises(ValueError):
        gate.validate(finding(), set())

def test_all_checks_enable_validation():
    gate = HumanValidationGate()
    f = gate.validate(finding(), set(gate.REQUIRED_CHECKS))
    assert f.human_validated is True
