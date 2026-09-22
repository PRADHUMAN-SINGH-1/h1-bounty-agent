from pathlib import Path


def test_research_runner_exists():
    text = Path("scripts/research_runner.py").read_text(encoding="utf-8")
    assert "claim_next_research_job" in text
    assert "run_cycle" in text
    assert "status" in text


def test_research_jobs_are_queued_without_render_background_execution():
    text = Path("api/index.py").read_text(encoding="utf-8")
    start = text.index('@app.post("/api/research/jobs")')
    end = text.index('@app.get("/api/research/jobs/{job_id}")')
    block = text[start:end]
    assert "create_research_job" in block
    assert "background_tasks" not in block
    assert "status_code=202" in block


def test_open_source_toolchain_adapters_exist():
    text = Path("src/h1_agent/toolchain.py").read_text(encoding="utf-8")
    for tool in ("subfinder", "httpx", "katana", "nuclei", "gau", "waybackurls"):
        assert tool in text
    assert "target_is_in_scope" in text
    assert "exclude-tags" in text


def test_toolchain_config_exists():
    text = Path("src/h1_agent/config.py").read_text(encoding="utf-8")
    assert "toolchain_enabled" in text
    assert "toolchain_max_roots" in text


def test_research_runner_workflow_exists():
    text = Path(".github/workflows/research-runner.yml").read_text(encoding="utf-8")
    assert "*/5 * * * *" in text
    assert "scripts/research_runner.py" in text
    assert "RESEARCH_DATABASE_URL" in text
    assert "H1_ENABLE_SUBMISSION: \"false\"" in text
