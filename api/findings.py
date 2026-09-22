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

app = FastAPI(title="H1 Findings API", version="0.4.0")

_STATE = Path("/tmp/h1-findings.json")


def _auth(authorization: str | None) -> None:
    expected_user = os.getenv("DASHBOARD_USER", "")
    expected_password = os.getenv("DASHBOARD_PASSWORD", "")
    if not expected_user or not expected_password:
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
        hmac.compare_digest(supplied_user, expected_user)
        and hmac.compare_digest(supplied_password, expected_password)
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


def _read() -> dict[str, Any]:
    try:
        return json.loads(_STATE.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return {"findings": {}}


def _write(data: dict[str, Any]) -> None:
    _STATE.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")


def _verify_token(token: str | None) -> None:
    secret = os.getenv("DASHBOARD_SECRET", "")
    supplied = token or ""
    bucket = int(time.time() // 300)
    for candidate_bucket in (bucket, bucket - 1):
        expected = hmac.new(
            secret.encode(),
            str(candidate_bucket).encode(),
            hashlib.sha256,
        ).hexdigest()
        if supplied and hmac.compare_digest(supplied, expected):
            return
    raise HTTPException(status_code=403, detail="Invalid or expired action token.")


@app.get("/")
def list_findings(authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _auth(authorization)
    state = _read()
    rows = list(state.get("findings", {}).values())
    rows.sort(key=lambda row: int(row.get("id", 0)), reverse=True)
    return {
        "findings": rows,
        "durable_storage": False,
        "action_token": _action_token(),
    }


@app.get("/{finding_id}")
def get_finding(
    finding_id: int,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    _auth(authorization)
    state = _read()
    row = state.get("findings", {}).get(str(finding_id))
    if row is None:
        raise HTTPException(status_code=404, detail="Finding not found.")
    return row


@app.post("/{finding_id}/approve")
def approve_finding(
    finding_id: int,
    authorization: str | None = Header(default=None),
    x_action_token: str | None = Header(default=None),
) -> dict[str, Any]:
    _auth(authorization)
    _verify_token(x_action_token)

    state = _read()
    row = state.get("findings", {}).get(str(finding_id))
    if row is None:
        raise HTTPException(status_code=404, detail="Finding not found.")

    required = ("title", "summary", "impact", "evidence", "reproduction")
    for key in required:
        if not row.get(key):
            raise HTTPException(status_code=400, detail=f"Finding is incomplete: {key}.")

    # Lazy import: the dashboard GET path never imports the HackerOne/research stack.
    try:
        from h1_agent.hackerone import HackerOneClient
        from h1_agent.config import Settings
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
    _write(state)
    return {"status": "approved", "finding": row}


@app.post("/{finding_id}/submit")
def submit_finding(
    finding_id: int,
    authorization: str | None = Header(default=None),
    x_action_token: str | None = Header(default=None),
) -> dict[str, Any]:
    _auth(authorization)
    _verify_token(x_action_token)

    if os.getenv("H1_ENABLE_SUBMISSION", "false").strip().lower() != "true":
        raise HTTPException(status_code=403, detail="HackerOne submission is disabled.")

    state = _read()
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
    _write(state)

    return {"status": "submitted", "report": payload}
