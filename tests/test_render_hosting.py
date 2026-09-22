from pathlib import Path

from h1_agent.config import Settings
from h1_agent.store import Store


def test_render_blueprint_contains_web_cron_database():
    text = Path("render.yaml").read_text(encoding="utf-8")
    assert "type: web" in text
    assert "type: cron" in text
    assert "databases:" in text
    assert "fromDatabase:" in text
    assert "connectionString" in text
    assert "uvicorn api.index:app --host 0.0.0.0 --port $PORT" in text


def test_store_defaults_to_json_without_database(monkeypatch, tmp_path):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "state.json"))
    store = Store(Settings())
    assert store.durable is False
    store.close()


def test_render_cron_module_exists():
    from h1_agent.render_cron import main
    assert callable(main)
