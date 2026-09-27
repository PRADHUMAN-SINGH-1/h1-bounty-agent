from pathlib import Path


def test_production_submission_and_autonomous_modes_are_off_by_default():
    render = Path("render.yaml").read_text(encoding="utf-8")
    assert 'key: H1_ENABLE_SUBMISSION\n        value: "false"' in render
    assert 'key: AUTONOMOUS_RESEARCH\n        value: "false"' in render


def test_validation_requires_confirmed_reproduction_gate():
    source = Path("src/h1_agent/validation.py").read_text(encoding="utf-8")
    assert "from .research_gates import CONFIRMED" in source
    assert "finding is not CONFIRMED by the reproduction gate" in source
    assert "duplicate match prevents submission" in source


def test_autonomous_research_requires_explicit_allowlist():
    source = Path("src/h1_agent/config.py").read_text(encoding="utf-8")
    assert "if not self.research_program_allowlist:" in source
    assert "RESEARCH_PROGRAM_ALLOWLIST" in source


def test_security_research_contract_exists():
    policy = Path("SECURITY_RESEARCH_POLICY.md").read_text(encoding="utf-8")
    for required in (
        "Program policy",
        "Structured allowlist",
        "exclusions/instructions",
        "CONFIRMED",
        "UNCONFIRMED",
        "duplicate screening",
        "DoS/DDoS",
    ):
        assert required in policy
