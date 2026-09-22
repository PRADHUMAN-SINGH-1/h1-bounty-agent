from pathlib import Path

from h1_agent.pattern_library import PATTERNS, pattern_evidence, relevant_patterns


def test_pattern_library_has_high_value_classes():
    names = {item.name for item in PATTERNS}
    assert "object-authorization-boundary" in names
    assert "ssrf-to-sensitive-boundary" in names
    assert "business-logic-state-transition" in names
    assert len(PATTERNS) >= 12


def test_pattern_library_turns_into_evidence():
    evidence = pattern_evidence()
    assert len(evidence) == len(PATTERNS)
    assert all(item.name == "bounty_pattern_reference" for item in evidence)


def test_pattern_matching_uses_observed_evidence():
    matches = relevant_patterns(
        [
            type("E", (), {"name": "business_object", "value": "tenant_id=123"})(),
            type("E", (), {"name": "authorization_differential", "value": "account B allowed"})(),
        ]
    )
    names = {item.name for item in matches}
    assert "object-authorization-boundary" in names


def test_auto_submission_is_explicit_and_strict():
    config = Path("src/h1_agent/config.py").read_text(encoding="utf-8")
    worker = Path("src/h1_agent/worker.py").read_text(encoding="utf-8")
    assert 'auto_submit_findings: bool = _bool("AUTO_SUBMIT_FINDINGS", False)' in config
    assert "confidence < 0.90" in worker
    assert 'severity not in {"high", "critical"}' in worker
    assert "DRY_RUN" in config or "dry_run" in config


def test_global_hunt_button_exists():
    html = Path("public/index.html").read_text(encoding="utf-8")
    assert 'id="run">Hunt automatically' in html
    assert "async function huntAutomatically()" in html
