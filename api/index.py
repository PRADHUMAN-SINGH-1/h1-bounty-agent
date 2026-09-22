from __future__ import annotations

from fastapi import FastAPI

from h1_agent.config import Settings
from h1_agent.llm import LLMClient
from h1_agent.store import Store

app = FastAPI(title="H1 Bounty Agent", version="0.4.0")


@app.get("/")
def health() -> dict:
    settings = Settings()
    store = Store(settings)
    try:
        return {
            "service": "h1-bounty-agent",
            "status": "online",
            "version": "0.4.0",
            "dry_run": settings.dry_run,
            "active_tests": settings.allow_active_tests,
            "autonomous_research": settings.autonomous_research,
            "submission_enabled": settings.enable_submission,
            "durable_storage": store.durable,
            "llm_provider": settings.llm_provider,
            "llm_available": LLMClient(settings).available(),
        }
    finally:
        store.close()
