from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def test_research_target_deadline_is_enforced():
    source = (REPO / "src/h1_agent/research.py").read_text(encoding="utf-8")
    assert "self._deadline" in source
    assert "research_target_timeout_seconds" in source
    assert "_request_timeout" in source


def test_worker_passes_toolchain_limits_and_reports_phases():
    source = (REPO / "src/h1_agent/worker.py").read_text(encoding="utf-8")
    assert "httpx_timeout=settings.toolchain_httpx_timeout_seconds" in source
    assert "katana_timeout=settings.toolchain_katana_timeout_seconds" in source
    assert "nuclei_timeout=settings.toolchain_nuclei_timeout_seconds" in source
    assert '"phase": "finding_evidence"' in source
    assert '"phase": "triaging_evidence"' in source
    assert '"phase": "drafting_report"' in source


def test_dashboard_has_phase_aware_research_polling():
    source = (REPO / "public/index.html").read_text(encoding="utf-8")
    assert 'const phase=p.phase||"running"' in source
    assert "Research job exceeded the dashboard timeout" in source
