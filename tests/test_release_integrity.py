from pathlib import Path


REPO = Path(__file__).resolve().parents[1]


def test_python_sources_compile():
    source_root = REPO / "src" / "h1_agent"
    for path in sorted(source_root.glob("*.py")):
        compile(path.read_text(encoding="utf-8"), str(path), "exec")
    compile((REPO / "api" / "index.py").read_text(encoding="utf-8"), "api/index.py", "exec")


def test_dashboard_uses_event_binding_for_all_buttons():
    html = (REPO / "public" / "index.html").read_text(encoding="utf-8")
    assert "onclick=" not in html
    for action in ("connectBtn", "run", "refreshBtn", "logoutBtn", "scanBtn"):
        assert f'id="{action}"' in html
    for action in ("data-view-id", "data-approve-id", "data-submit-id", "data-research-handle", "data-assess-handle"):
        assert action in html
    assert html.count('addEventListener("click"') >= 8


def test_runtime_defaults_are_safe(monkeypatch):
    monkeypatch.setenv("REQUESTS_PER_SECOND", "")
    monkeypatch.setenv("AUTONOMOUS_MAX_PROGRAMS", "")
    monkeypatch.setenv("AUTONOMOUS_MAX_TARGETS_PER_PROGRAM", "")
    from h1_agent.config import Settings
    settings = Settings()
    assert settings.requests_per_second == 1.0
    assert settings.autonomous_max_programs == 3
    assert settings.autonomous_max_targets_per_program == 2


def test_cli_uses_current_llm_and_active_gate():
    source = (REPO / "src" / "h1_agent" / "cli.py").read_text(encoding="utf-8")
    assert "from .llm import LocalLLM" not in source
    assert "from .llm import LLMClient" in source
    assert "settings.allow_active_tests" in source
    assert "engine.run(args.target, active=True)" in source


def test_report_module_compiles():
    compile((REPO / "src" / "h1_agent" / "reporting.py").read_text(encoding="utf-8"), "reporting.py", "exec")
