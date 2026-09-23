from pathlib import Path


def test_dashboard_never_calls_synchronous_worker():
    html = Path("public/index.html").read_text(encoding="utf-8")
    assert 'request("/api/worker"' not in html
    assert 'request("/api/discovery/jobs"' in html
    assert "pollDiscoveryJob" in html


def test_discovery_api_is_async():
    api = Path("api/index.py").read_text(encoding="utf-8")
    assert '@app.post("/api/discovery/jobs")' in api
    start = api.index('@app.post("/api/discovery/jobs")')
    end = api.index('@app.post("/api/research/jobs")')
    block = api[start:end]
    assert "BackgroundTasks" in block
    assert "status_code=202" in block


def test_compatibility_worker_is_also_queued():
    api = Path("api/index.py").read_text(encoding="utf-8")
    start = api.index('@app.post("/api/worker")')
    end = api.index('@app.get("/api/diagnostics")')
    block = api[start:end]
    assert "create_research_job" in block
    assert "background_tasks.add_task" in block
    assert "run_cycle(" not in block
