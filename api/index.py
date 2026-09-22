from __future__ import annotations

import os
from fastapi import FastAPI, Header, HTTPException

from h1_agent.config import Settings
from h1_agent.hackerone import HackerOneClient

app = FastAPI(title="H1 Bounty Agent", version="0.3.0")


def _cron_guard(authorization: str | None) -> None:
    secret = os.getenv("CRON_SECRET")
    if not secret:
        return
    if authorization != f"Bearer {secret}":
        raise HTTPException(status_code=401, detail="Unauthorized")


@app.get("/")
def health() -> dict:
    return {
        "service": "h1-bounty-agent",
        "status": "online",
        "version": "0.3.0",
        "dry_run": Settings().dry_run,
        "submission_enabled": Settings().enable_submission,
    }


@app.get("/api/programs")
def programs() -> dict:
    settings = Settings()
    client = HackerOneClient(settings)
    try:
        return client.programs(page=1, page_size=25)
    finally:
        client.close()


@app.get("/api/cron")
def cron(authorization: str | None = Header(default=None)) -> dict:
    _cron_guard(authorization)
    settings = Settings()
    client = HackerOneClient(settings)
    try:
        payload = client.programs(page=1, page_size=100)
        programs = payload.get("data", [])
        summary = []
        for item in programs:
            attrs = item.get("attributes", {})
            summary.append({
                "handle": attrs.get("handle"),
                "name": attrs.get("name"),
                "state": attrs.get("state"),
            })
        # This endpoint is intentionally discovery-only for now. It never
        # launches target testing or submits a HackerOne report.
        return {
            "status": "ok",
            "program_count": len(summary),
            "programs": summary,
            "next_stage": "scope-aware research worker",
        }
    finally:
        client.close()
