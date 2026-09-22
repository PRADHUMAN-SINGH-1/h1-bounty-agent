from pathlib import Path


def test_postgres_uses_autocommit_and_migrations():
    text = Path("src/h1_agent/postgres_store.py").read_text(encoding="utf-8")
    assert "autocommit=True" in text
    assert "ADD COLUMN IF NOT EXISTS" in text
    assert "Persistent findings storage is unavailable." in text


def test_readme_mentions_postgres_queue_resilience():
    text = Path("README.md").read_text(encoding="utf-8")
    assert "Postgres schema migration/retry hardening" in text
