from pathlib import Path


def test_findings_endpoint_returns_storage_diagnostics_instead_of_generic_500():
    text = Path("api/index.py").read_text(encoding="utf-8")
    start = text.index('@app.get("/api/findings")')
    end = text.index('@app.get("/api/findings/{finding_id}")')
    block = text[start:end]
    assert "except Exception as exc:" in block
    assert '"storage_error": storage_error' in block
    assert '"findings": rows' in block


def test_postgres_findings_query_uses_stable_projection_and_timeouts():
    text = Path("src/h1_agent/postgres_store.py").read_text(encoding="utf-8")
    assert 'options="-c statement_timeout=15000 -c lock_timeout=3000"' in text
    assert "SELECT id, program_handle, target, title, severity, state," in text
    assert "FROM h1_findings" in text


def test_cron_triggers_background_work():
    text = Path("api/index.py").read_text(encoding="utf-8")
    start = text.index('@app.get("/api/cron")')
    end = len(text)
    block = text[start:end]
    assert "BackgroundTasks" in block
    assert "_run_research_job_background" in block
    assert "_run_autonomous_research_background" in block


def test_scheduler_uses_render_trigger_not_direct_database_secrets():
    text = Path(".github/workflows/research-runner.yml").read_text(encoding="utf-8")
    assert "H1_AGENT_URL" in text
    assert "CRON_SECRET" in text
    assert "RESEARCH_DATABASE_URL" not in text
    assert "HACKERONE_API_TOKEN" not in text
    assert "/api/cron" in text
