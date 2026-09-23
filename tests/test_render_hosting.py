from pathlib import Path

from h1_agent.config import Settings
from h1_agent.store import Store


def test_render_blueprint_contains_free_web_and_database():
    text = Path("render.yaml").read_text(encoding="utf-8")
    assert "type: web" in text
    assert "plan: free" in text
    assert "databases:" in text
    assert "fromDatabase:" in text
    assert "connectionString" in text
    assert "uvicorn api.index:app --host 0.0.0.0 --port $PORT" in text
    assert "type: cron" not in text


def test_github_research_runner_is_configured():
    text = Path(".github/workflows/research-runner.yml").read_text(encoding="utf-8")
    assert 'cron: "*/5 * * * *"' in text
    assert "/api/cron" in text
    assert "H1_AGENT_URL" in text
    assert "CRON_SECRET" in text


def test_store_defaults_to_json_without_database(monkeypatch, tmp_path):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "state.json"))
    store = Store(Settings())
    assert store.durable is False
    store.close()


def test_render_cron_module_exists():
    from h1_agent.render_cron import main
    assert callable(main)
