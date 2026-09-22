from __future__ import annotations

import os

from fastapi import FastAPI, Header, HTTPException

from h1_agent.config import Settings
from h1_agent.worker import run_cycle

app = FastAPI(title="H1 Bounty Agent Cron", version="0.4.0")


def _guard(authorization: str | None) -> None:
    secret = os.getenv("CRON_SECRET", "")
    if not secret:
        raise HTTPException(status_code=503, detail="CRON_SECRET is not configured.")
    if authorization != f"Bearer {secret}":
        raise HTTPException(status_code=401, detail="Unauthorized")


@app.get("/")
def run_cron(authorization: str | None = Header(default=None)) -> dict:
    _guard(authorization)
    return run_cycle(Settings())
