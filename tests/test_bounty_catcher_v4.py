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


def test_research_runner_does_not_require_llm_token_for_evidence_collection():
    workflow = Path(".github/workflows/research-runner.yml").read_text(encoding="utf-8")
    assert '[ -z "$HF_TOKEN" ]' in workflow
    assert 'HF_TOKEN is not configured' in workflow
    assert 'exit 1' in workflow
    assert 'DATABASE_URL' in workflow
    assert 'HACKERONE_API_TOKEN' in workflow


def test_findings_and_approval_buttons_use_real_finding_id():
    html = Path("public/index.html").read_text(encoding="utf-8")
    assert 'data-view-id="${x.id}"' not in html
    assert 'data-approve-id="${x.id}"' not in html
    assert "data-view-id=\"\'+esc(x.id)+\'\"" in html
    assert "data-approve-id=\"\'+esc(x.id)+\'\"" in html
