from __future__ import annotations

from fastapi import Depends, FastAPI, Header
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from h1_agent.config import Settings
from h1_agent.web_auth import require_basic, verify_action_token
from h1_agent.worker import run_cycle

app = FastAPI(title="H1 Worker", version="0.4.0")
basic = HTTPBasic(auto_error=False)


def _auth(credentials: HTTPBasicCredentials | None = Depends(basic)) -> None:
    settings = Settings()
    require_basic(credentials, settings.dashboard_user, settings.dashboard_password)


@app.post("/", dependencies=[Depends(_auth)])
def worker(x_action_token: str | None = Header(default=None)) -> dict:
    settings = Settings()
    verify_action_token(x_action_token, settings.dashboard_secret)
    return run_cycle(settings)
