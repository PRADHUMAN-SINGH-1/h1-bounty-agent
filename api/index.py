from __future__ import annotations

from fastapi import FastAPI

from h1_agent.config import Settings

app = FastAPI(title="H1 Bounty Agent", version="0.3.0")


@app.get("/")
def health() -> dict:
    settings = Settings()
    return {
        "service": "h1-bounty-agent",
        "status": "online",
        "version": "0.3.0",
        "dry_run": settings.dry_run,
        "active_tests": settings.allow_active_tests,
        "submission_enabled": settings.enable_submission,
    }
