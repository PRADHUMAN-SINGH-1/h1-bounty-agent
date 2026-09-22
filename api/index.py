from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, HTTPException

app = FastAPI(title="H1 Bounty Agent", version="0.4.0")

_STATE = Path("/tmp/h1-findings.json")


def _read_state() -> dict[str, Any]:
    try:
        return json.loads(_STATE.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return {"findings": {}}


def _write_state(state: dict[str, Any]) -> None:
    _STATE.write_text(json.dumps(state, ensure_ascii=False), encoding="utf-8")


def _require_basic(authorization: str | None) -> None:
    user = os.getenv("DASHBOARD_USER", "")
    password = os.getenv("DASHBOARD_PASSWORD", "")
    if not user or not password:
        raise HTTPException(status_code=503, detail="Dashboard credentials are not configured.")
    if not authorization or not authorization.startswith("Basic "):
        raise HTTPException(
            status_code=401,
            detail="Authentication required.",
            headers={"WWW-Authenticate": "Basic"},
        )
    try:
        decoded = base64.b64decode(authorization[6:]).decode("utf-8")
        supplied_user, supplied_password = decoded.split(":", 1)
    except Exception as exc:
        raise HTTPException(status_code=401, detail="Invalid authentication header.") from exc
    if not (
        hmac.compare_digest(supplied_user, user)
        and hmac.compare_digest(supplied_password, password)
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials.",
            headers={"WWW-Authenticate": "Basic"},
        )


def _action_token() -> str:
    secret = os.getenv("DASHBOARD_SECRET", "")
    if not secret:
        raise HTTPException(status_code=503, detail="DASHBOARD_SECRET is not configured.")
    bucket = int(time.time() // 300)
    return hmac.new(secret.encode(), str(bucket).encode(), hashlib.sha256).hexdigest()


def _verify_action_token(token: str | None) -> None:
    secret = os.getenv("DASHBOARD_SECRET", "")
    if not secret:
        raise HTTPException(status_code=503, detail="DASHBOARD_SECRET is not configured.")
    supplied = token or ""
    bucket = int(time.time() // 300)
    for candidate in (bucket, bucket - 1):
        expected = hmac.new(secret.encode(), str(candidate).encode(), hashlib.sha256).hexdigest()
        if supplied and hmac.compare_digest(supplied, expected):
            return
    raise HTTPException(status_code=403, detail="Invalid or expired action token.")


@app.get("/api")
def health() -> dict[str, Any]:
    return {
        "service": "h1-bounty-agent",
        "status": "online",
        "version": "0.4.0",
        "dry_run": os.getenv("DRY_RUN", "true"),
        "active_tests": os.getenv("ALLOW_ACTIVE_TESTS", "false"),
        "autonomous_research": os.getenv("AUTONOMOUS_RESEARCH", "false"),
        "submission_enabled": os.getenv("H1_ENABLE_SUBMISSION", "false"),
    }


@app.get("/api/findings")
def list_findings(authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_basic(authorization)
    state = _read_state()
    rows = list(state.get("findings", {}).values())
    rows.sort(key=lambda row: int(row.get("id", 0)), reverse=True)
    return {
        "findings": rows,
        "durable_storage": False,
        "action_token": _action_token(),
    }


@app.get("/api/findings/{finding_id}")
def get_finding(
    finding_id: int,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_basic(authorization)
    row = _read_state().get("findings", {}).get(str(finding_id))
    if row is None:
        raise HTTPException(status_code=404, detail="Finding not found.")
    return row


@app.post("/api/findings/{finding_id}/approve")
def approve_finding(
    finding_id: int,
    authorization: str | None = Header(default=None),
    x_action_token: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_basic(authorization)
    _verify_action_token(x_action_token)

    state = _read_state()
    row = state.get("findings", {}).get(str(finding_id))
    if row is None:
        raise HTTPException(status_code=404, detail="Finding not found.")

    for key in ("title", "summary", "impact", "evidence", "reproduction"):
        if not row.get(key):
            raise HTTPException(status_code=400, detail=f"Finding is incomplete: {key}.")

    try:
        from h1_agent.config import Settings
        from h1_agent.hackerone import HackerOneClient
        from h1_agent.scope import normalize_scopes, target_is_in_scope
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Backend dependency failed: {exc}") from exc

    settings = Settings()
    api = HackerOneClient(settings)
    try:
        scopes = normalize_scopes(api.structured_scopes(row["program_handle"]))
        ok, asset, reason = target_is_in_scope(row["target"], scopes)
        if not ok or asset is None or not asset.eligible_for_submission:
            raise HTTPException(status_code=400, detail=f"Current scope check failed: {reason}")
    finally:
        api.close()

    row["state"] = "approved"
    row["approved_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    state["findings"][str(finding_id)] = row
    _write_state(state)
    return {"status": "approved", "finding": row}


@app.post("/api/findings/{finding_id}/submit")
def submit_finding(
    finding_id: int,
    authorization: str | None = Header(default=None),
    x_action_token: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_basic(authorization)
    _verify_action_token(x_action_token)

    if os.getenv("H1_ENABLE_SUBMISSION", "false").strip().lower() != "true":
        raise HTTPException(status_code=403, detail="HackerOne submission is disabled.")

    state = _read_state()
    row = state.get("findings", {}).get(str(finding_id))
    if row is None:
        raise HTTPException(status_code=404, detail="Finding not found.")
    if row.get("state") != "approved":
        raise HTTPException(status_code=400, detail="Only an approved finding can be submitted.")

    try:
        from h1_agent.config import Settings
        from h1_agent.hackerone import HackerOneClient
        from h1_agent.models import Evidence, Finding
        from h1_agent.reporting import markdown_report
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Backend dependency failed: {exc}") from exc

    finding = Finding(
        program_handle=row["program_handle"],
        target=row["target"],
        title=row["title"],
        severity=row.get("severity"),
        state="approved",
        summary=row["summary"],
        impact=row["impact"],
        reproduction=row["reproduction"],
        evidence=[Evidence(**item) for item in row["evidence"]],
        structured_scope_id=row.get("structured_scope_id"),
        weakness_id=row.get("weakness_id"),
    )

    settings = Settings()
    api = HackerOneClient(settings)
    try:
        payload = api.create_report(
            team_handle=finding.program_handle,
            title=finding.title,
            vulnerability_information=markdown_report(finding),
            impact=finding.impact,
            severity_rating=finding.severity or "none",
            weakness_id=finding.weakness_id,
            structured_scope_id=(
                int(finding.structured_scope_id)
                if str(finding.structured_scope_id or "").isdigit()
                else None
            ),
        )
    finally:
        api.close()

    row["state"] = "submitted"
    row["report_json"] = payload
    row["submitted_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    row["h1_report_id"] = str(payload.get("data", {}).get("id") or "")
    state["findings"][str(finding_id)] = row
    _write_state(state)
    return {"status": "submitted", "report": payload}


@app.get("/api/programs")
def programs(authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_basic(authorization)
    try:
        from h1_agent.config import Settings
        from h1_agent.hackerone import HackerOneClient
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Backend dependency failed: {exc}") from exc

    settings = Settings()
    api = HackerOneClient(settings)
    try:
        return api.programs(page=1, page_size=25)
    finally:
        api.close()


@app.post("/api/worker")
def worker(
    authorization: str | None = Header(default=None),
    x_action_token: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_basic(authorization)
    _verify_action_token(x_action_token)
    try:
        from h1_agent.config import Settings
        from h1_agent.worker import run_cycle
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Backend dependency failed: {exc}") from exc
    return run_cycle(Settings())


@app.get("/api/cron")
def cron(authorization: str | None = Header(default=None)) -> dict[str, Any]:
    secret = os.getenv("CRON_SECRET", "")
    if not secret:
        raise HTTPException(status_code=503, detail="CRON_SECRET is not configured.")
    if authorization != f"Bearer {secret}":
        raise HTTPException(status_code=401, detail="Unauthorized")
    try:
        from h1_agent.config import Settings
        from h1_agent.worker import run_cycle
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Backend dependency failed: {exc}") from exc
    return run_cycle(Settings())
