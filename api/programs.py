from __future__ import annotations

from fastapi import Depends, FastAPI
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from h1_agent.config import Settings
from h1_agent.hackerone import HackerOneClient
from h1_agent.web_auth import require_basic

app = FastAPI(title="H1 Bounty Agent Programs", version="0.4.0")
basic = HTTPBasic(auto_error=False)


def _auth(credentials: HTTPBasicCredentials | None = Depends(basic)) -> None:
    settings = Settings()
    require_basic(credentials, settings.dashboard_user, settings.dashboard_password)


@app.get("/", dependencies=[Depends(_auth)])
def programs() -> dict:
    settings = Settings()
    client = HackerOneClient(settings)
    try:
        return client.programs(page=1, page_size=25)
    finally:
        client.close()
