from __future__ import annotations

from fastapi import FastAPI

from h1_agent.config import Settings
from h1_agent.hackerone import HackerOneClient

app = FastAPI(title="H1 Bounty Agent Programs", version="0.3.0")


@app.get("/")
def programs() -> dict:
    settings = Settings()
    client = HackerOneClient(settings)
    try:
        return client.programs(page=1, page_size=25)
    finally:
        client.close()
