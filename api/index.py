from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
import unicodedata
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse

app = FastAPI(title="H1 Bounty Agent", version="0.4.0")
_STATE = Path("/tmp/h1-findings.json")
_SESSION_COOKIE = "h1_session"


def _read_state() -> dict[str, Any]:
    try:
        return json.loads(_STATE.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return {"findings": {}}


def _write_state(state: dict[str, Any]) -> None:
    _STATE.write_text(json.dumps(state, ensure_ascii=False), encoding="utf-8")


def _normalize_credential(value: str) -> str:
    value = unicodedata.normalize("NFKC", value)
    value = value.replace("\\r", "").replace("\\n", "").strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"\"", "'"}:
        value = value[1:-1]
    return value


def _password_matches(supplied: str, configured: str, secret: str) -> bool:
    if configured and hmac.compare_digest(supplied, configured):
        return True
    return bool(secret) and hmac.compare_digest(supplied, secret)


def _sign(value: str) -> str:
    secret = os.getenv("DASHBOARD_SECRET", "")
    if not secret:
        raise HTTPException(status_code=503, detail="DASHBOARD_SECRET is not configured.")
    return hmac.new(secret.encode(), value.encode(), hashlib.sha256).hexdigest()


def _make_session(username: str, ttl: int = 8 * 60 * 60) -> str:
    expires = int(time.time()) + ttl
    payload = f"{username}.{expires}"
    raw = base64.urlsafe_b64encode(payload.encode()).decode().rstrip("=")
    return f"{raw}.{_sign(raw)}"


def _require_session(request: Request) -> None:
    user = _normalize_credential(os.getenv("DASHBOARD_USER", "")).lower()
    dashboard_secret = _normalize_credential(os.getenv("DASHBOARD_SECRET", ""))
    if not user or not dashboard_secret:
        raise HTTPException(status_code=503, detail="Dashboard authentication is not configured.")

    cookie = request.cookies.get(_SESSION_COOKIE)
    if not cookie or "." not in cookie:
        raise HTTPException(status_code=401, detail="Please connect to the dashboard.")

    raw, supplied_sig = cookie.rsplit(".", 1)
    expected = _sign(raw)
    if not hmac.compare_digest(supplied_sig, expected):
        raise HTTPException(status_code=401, detail="Session expired. Please connect again.")

    try:
        padding = "=" * (-len(raw) % 4)
        username, expires_text = base64.urlsafe_b64decode((raw + padding).encode()).decode().rsplit(".", 1)
        if int(expires_text) < int(time.time()) or not hmac.compare_digest(username.lower(), user):
            raise HTTPException(status_code=401, detail="Session expired. Please connect again.")
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=401, detail="Invalid session.") from exc


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


@app.post("/api/auth/login")
async def login(request: Request) -> JSONResponse:
    try:
        body = await request.json()
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid JSON.") from exc

    username = _normalize_credential(str(body.get("username", ""))).lower()
    password = _normalize_credential(str(body.get("password", "")))
    expected_user = _normalize_credential(os.getenv("DASHBOARD_USER", "")).lower()
    expected_password = _normalize_credential(os.getenv("DASHBOARD_PASSWORD", ""))
    dashboard_secret = _normalize_credential(os.getenv("DASHBOARD_SECRET", ""))

    if not expected_user or not dashboard_secret:
        raise HTTPException(status_code=503, detail="Dashboard authentication is not configured.")

    if not (
        hmac.compare_digest(username, expected_user)
        and _password_matches(password, expected_password, dashboard_secret)
    ):
        raise HTTPException(status_code=401, detail="Invalid dashboard credentials.")

    response = JSONResponse({"status": "ok", "action_token": _action_token()})
    response.set_cookie(
        key=_SESSION_COOKIE,
        value=_make_session(username),
        max_age=8 * 60 * 60,
        httponly=True,
        secure=True,
        samesite="strict",
        path="/",
    )
    return response


@app.post("/api/auth/logout")
def logout() -> JSONResponse:
    response = JSONResponse({"status": "logged_out"})
    response.delete_cookie(_SESSION_COOKIE, path="/")
    return response


@app.get("/api")
def health() -> dict[str, Any]:
    return {
        "service": "h1-bounty-agent",
        "status": "online",
        "version": "0.4.0",
        "dry_run": os.getenv("DRY_RUN", "true"),
        "active_tests": os.getenv("ALLOW_ACTIVE_TESTS", "false"),
        "autonomous_research": os.getenv("AUTONOMOUS_RESEARCH", "false"),
        "autonomous_passive_research": os.getenv("AUTONOMOUS_PASSIVE_RESEARCH", "false"),
        "submission_enabled": os.getenv("H1_ENABLE_SUBMISSION", "false"),
    }


@app.get("/api/findings")
def list_findings(request: Request) -> dict[str, Any]:
    _require_session(request)
    state = _read_state()
    rows = list(state.get("findings", {}).values())
    rows.sort(key=lambda row: int(row.get("id", 0)), reverse=True)
    return {"findings": rows, "durable_storage": False, "action_token": _action_token()}


@app.get("/api/findings/{finding_id}")
def get_finding(finding_id: int, request: Request) -> dict[str, Any]:
    _require_session(request)
    row = _read_state().get("findings", {}).get(str(finding_id))
    if row is None:
        raise HTTPException(status_code=404, detail="Finding not found.")
    return row


@app.post("/api/findings/{finding_id}/approve")
def approve_finding(
    finding_id: int,
    request: Request,
    x_action_token: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_session(request)
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
    request: Request,
    x_action_token: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_session(request)
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
        from h1_agent.validation import require_human_approval
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
        metadata=row.get("metadata") or {},
    )

    try:
        require_human_approval(finding)
    except (ValueError, PermissionError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

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
def programs(request: Request) -> dict[str, Any]:
    _require_session(request)
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
async def worker(request: Request, x_action_token: str | None = Header(default=None)) -> dict[str, Any]:
    _require_session(request)
    _verify_action_token(x_action_token)
    try:
        from h1_agent.config import Settings
        from h1_agent.worker import run_cycle

        requested_programs: set[str] | None = None
        try:
            body = await request.json()
            if isinstance(body, dict) and isinstance(body.get("programs"), list):
                requested_programs = {
                    str(handle).strip()
                    for handle in body["programs"]
                    if str(handle).strip()
                } or None
        except Exception:
            requested_programs = None

        return run_cycle(Settings(), requested_programs=requested_programs)
    except Exception as exc:
        return {
            "status": "error",
            "error_type": "endpoint",
            "error": f"{exc.__class__.__name__}: {exc}",
        }



@app.get("/api/diagnostics")
def diagnostics(request: Request) -> dict[str, Any]:
    _require_session(request)
    from h1_agent.config import Settings
    settings = Settings()
    result: dict[str, Any] = {
        "hackerone_username_configured": bool(settings.hackerone_username),
        "hackerone_token_configured": bool(settings.hackerone_api_token),
        "hackerone_base_url": settings.hackerone_base_url,
        "requests_per_second": settings.requests_per_second,
        "dry_run": settings.dry_run,
        "allow_active_tests": settings.allow_active_tests,
        "autonomous_research": settings.autonomous_research,
        "autonomous_passive_research": settings.autonomous_passive_research,
        "submission_enabled": settings.enable_submission,
    }
    try:
        from h1_agent.hackerone import HackerOneClient
        api = HackerOneClient(settings)
        try:
            payload = api.programs(page=1, page_size=1)
            result["hackerone_status"] = "ok"
            result["visible_programs"] = len(payload.get("data", []))
        finally:
            api.close()
    except Exception as exc:
        result["hackerone_status"] = "error"
        result["hackerone_error"] = f"{exc.__class__.__name__}: {exc}"
    return result


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
