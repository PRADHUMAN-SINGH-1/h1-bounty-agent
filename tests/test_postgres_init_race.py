from pathlib import Path


def test_postgres_schema_is_initialized_once_per_process():
    text = Path("src/h1_agent/postgres_store.py").read_text(encoding="utf-8")
    assert "_schema_ready" in text
    assert "_ensure_schema_once" in text
    assert "Running CREATE/ALTER TABLE on every dashboard read" in text
    assert "for attempt in range(3)" in text
