from __future__ import annotations

import os

from fastapi import FastAPI, Header, HTTPException

from h1_agent.config import Settings
from h1_agent.discovery import rank
from h1_agent.hackerone import HackerOneClient
from h1_agent.scope import normalize_scopes

app = FastAPI(title="H1 Bounty Agent Cron", version="0.3.0")


def _guard(authorization: str | None) -> None:
    secret = os.getenv("CRON_SECRET")
    if secret and authorization != f"Bearer {secret}":
        raise HTTPException(status_code=401, detail="Unauthorized")


@app.get("/")
def run_cron(authorization: str | None = Header(default=None)) -> dict:
    _guard(authorization)
    settings = Settings()
    client = HackerOneClient(settings)
    try:
        payload = client.programs(page=1, page_size=100)
        opportunities = []
        for item in payload.get("data", []):
            attrs = item.get("attributes", {})
            handle = attrs.get("handle")
            if not handle:
                continue
            try:
                scopes = normalize_scopes(client.structured_scopes(handle))
            except Exception:
                continue
            op = rank(
                handle,
                attrs.get("name", handle),
                attrs.get("state", ""),
                scopes,
            )
            opportunities.append(op.__dict__ | {"triage_score": op.score})

        opportunities.sort(key=lambda x: (-x["triage_score"], x["handle"]))

        return {
            "status": "ok",
            "checked_programs": len(opportunities),
            "top_opportunities": opportunities[:10],
            "next_stage": "authorization-aware research worker + durable finding storage",
        }
    finally:
        client.close()
