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
    for action in ("data-view-id", "data-approve-id", "data-full-research-handle"):
        assert action in html
    assert "data-submit-id" not in html
    assert "async function submitFinding" not in html
    assert "Approve & Submit" in html
    assert "data-research-handle" not in html
    assert "data-assess-handle" not in html
    assert "async function assessProgram" not in html
    assert 'body:JSON.stringify({programs:[handle],mode:"full"})' in html
    assert html.count('addEventListener("click"') >= 7
    assert (REPO / "src" / "h1_agent" / "authorization.py").exists()
    assert (REPO / "src" / "h1_agent" / "attack_surface.py").exists()



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


def test_full_research_pipeline_is_distinct_from_active_gate():
    worker = (REPO / "src" / "h1_agent" / "worker.py").read_text(encoding="utf-8")
    research = (REPO / "src" / "h1_agent" / "research.py").read_text(encoding="utf-8")
    api = (REPO / "api" / "index.py").read_text(encoding="utf-8")
    assert 'mode: str = ""' in worker
    assert '"selected-program-full-research"' in worker
    assert "selected_deep = True" in worker
    assert "deep=selected_deep" in worker
    assert "deep: bool = False" in research
    assert "if (deep or active) and home_response is not None" in research
    assert 'mode = str(body.get("mode", "") or "").strip().lower()' in api


def test_research_run_exposes_trace_and_no_finding_reason():
    worker = (REPO / "src" / "h1_agent" / "worker.py").read_text(encoding="utf-8")
    dashboard = (REPO / "public" / "index.html").read_text(encoding="utf-8")
    assert '"evidence_collected"' in worker
    assert '"checks_run"' in worker
    assert '"research_trace"' in worker
    assert "LLM evaluation returned status=" in worker
    assert "research_trace.checks" in dashboard



def test_research_job_errors_are_propagated_to_dashboard():
    api = (REPO / "api" / "index.py").read_text(encoding="utf-8")
    dashboard = (REPO / "public" / "index.html").read_text(encoding="utf-8")
    assert '"error": job_error' in api
    assert '"Research job failed without a reported error."' in api
    assert '((job.result||{}).error)' in dashboard


def test_llm_weakness_id_is_normalized_before_persistence():
    worker = (REPO / "src" / "h1_agent" / "worker.py").read_text(encoding="utf-8")
    assert "def _coerce_optional_int" in worker
    assert 'weakness_id = _coerce_optional_int(draft.get("weakness_id"))' in worker
    assert '"weakness_id": weakness_id' in worker


def test_llm_parser_accepts_trailing_model_text():
    from h1_agent.llm import LLMClient
    client = object.__new__(LLMClient)
    client.generate = lambda prompt: '{"status":"candidate"}\n{"ignored":"second"}'
    assert client.json("test") == {"status": "candidate"}


def test_llm_parser_accepts_fenced_json():
    from h1_agent.llm import LLMClient
    client = object.__new__(LLMClient)
    client.generate = lambda prompt: '```json\n{"status":"no_finding"}\n```'
    assert client.json("test") == {"status": "no_finding"}
