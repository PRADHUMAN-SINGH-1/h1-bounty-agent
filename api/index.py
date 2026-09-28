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

from fastapi import BackgroundTasks, FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse

app = FastAPI(title="H1 Bounty Agent", version="0.8.0")
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
    value = value.replace("\r", "").replace("\n", "").strip()
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


def _verify_cron_secret(authorization: str | None) -> None:
    secret = os.getenv("CRON_SECRET", "")
    if not secret:
        raise HTTPException(status_code=503, detail="CRON_SECRET is not configured.")
    if authorization != f"Bearer {secret}":
        raise HTTPException(status_code=401, detail="Unauthorized")


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

    if not (hmac.compare_digest(username, expected_user) and _password_matches(password, expected_password, dashboard_secret)):
        raise HTTPException(status_code=401, detail="Invalid dashboard credentials.")

    response = JSONResponse({"status": "ok", "action_token": _action_token()})
    response.set_cookie(key=_SESSION_COOKIE, value=_make_session(username), max_age=8 * 60 * 60, httponly=True, secure=True, samesite="strict", path="/")
    return response


@app.post("/api/auth/logout")
def logout() -> JSONResponse:
    response = JSONResponse({"status": "logged_out"})
    response.delete_cookie(_SESSION_COOKIE, path="/")
    return response


@app.get("/", include_in_schema=False)
def dashboard() -> FileResponse:
    path = Path(__file__).resolve().parent.parent / "public" / "index.html"
    if not path.exists():
        raise HTTPException(status_code=404, detail="Dashboard not found.")
    return FileResponse(path, media_type="text/html")


@app.get("/healthz", include_in_schema=False)
def healthz() -> dict[str, str]:
    return {"status": "ok", "commit": os.getenv("RENDER_GIT_COMMIT", "")}

@app.get("/api/cron/version")
def cron_version(authorization: str | None = Header(default=None)) -> dict[str, str]:
    _verify_cron_secret(authorization)
    return {
        "commit": os.getenv("RENDER_GIT_COMMIT", ""),
        "branch": os.getenv("RENDER_GIT_BRANCH", ""),
    }


@app.get("/api")
def health() -> dict[str, Any]:
    return {"service": "h1-bounty-agent", "status": "online", "version": "0.8.0", "dry_run": os.getenv("DRY_RUN", "true"), "active_tests": os.getenv("ALLOW_ACTIVE_TESTS", "false"), "autonomous_research": os.getenv("AUTONOMOUS_RESEARCH", "false"), "autonomous_passive_research": os.getenv("AUTONOMOUS_PASSIVE_RESEARCH", "false"), "submission_enabled": os.getenv("H1_ENABLE_SUBMISSION", "false")}


@app.get("/api/findings")
def list_findings(request: Request) -> dict[str, Any]:
    _require_session(request)
    from h1_agent.config import Settings
    from h1_agent.store import Store
    store = Store(Settings())
    try:
        try:
            rows = store.list_findings()
            storage_error = None
        except Exception as exc:
            rows = []
            storage_error = f"{exc.__class__.__name__}: {exc}"
        return {"findings": rows, "durable_storage": store.durable, "action_token": _action_token(), "storage_error": storage_error}
    finally:
        store.close()


@app.get("/api/findings/{finding_id}")
def get_finding(finding_id: int, request: Request) -> dict[str, Any]:
    _require_session(request)
    from h1_agent.config import Settings
    from h1_agent.store import Store
    store = Store(Settings())
    try:
        try:
            return store.get_finding(finding_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="Finding not found.") from exc
    finally:
        store.close()


@app.get("/api/cron/findings")
def cron_findings(authorization: str | None = Header(default=None)) -> dict[str, Any]:
    """Runner-only read path for autonomous hunt verification; requires CRON_SECRET."""
    _verify_cron_secret(authorization)
    from h1_agent.config import Settings
    from h1_agent.store import Store
    store = Store(Settings())
    try:
        rows = store.list_findings()
        return {"status": "ok", "count": len(rows), "findings": rows}
    finally:
        store.close()


@app.get("/api/cron/research/jobs/{job_id}")
def cron_research_job(job_id: str, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    """Runner-only research-job status path; keeps autonomous execution observable without dashboard credentials."""
    _verify_cron_secret(authorization)
    from h1_agent.config import Settings
    from h1_agent.store import Store
    store = Store(Settings())
    try:
        result = store.get_research_job(job_id)
        if result.get("status") == "error" and not result.get("error"):
            payload = result.get("result") or {}
            failures = [f"{item.get('program')}: {item.get('error')}" for item in payload.get("program_results", []) if item.get("error")]
            result["error"] = payload.get("error") or (" | ".join(failures) if failures else "Research job failed without a reported error.")
        return result
    finally:
        store.close()


@app.post("/api/findings/{finding_id}/approve")
def approve_finding(finding_id: int, request: Request, x_action_token: str | None = Header(default=None)) -> dict[str, Any]:
    _require_session(request)
    _verify_action_token(x_action_token)
    from h1_agent.config import Settings
    from h1_agent.hackerone import HackerOneAPIError, HackerOneClient
    from h1_agent.models import Evidence, Finding
    from h1_agent.scope import normalize_scopes, target_is_in_scope
    from h1_agent.store import Store
    from h1_agent.validation import validate_finding
    store = Store(Settings())
    try:
        row = store.get_finding(finding_id)
        for key in ("title", "summary", "impact", "evidence", "reproduction"):
            if not row.get(key):
                raise HTTPException(status_code=400, detail=f"Finding is incomplete: {key}.")
        candidate = Finding(program_handle=row["program_handle"], target=row["target"], title=row["title"], severity=row.get("severity"), state=row.get("state", "needs_review"), summary=row["summary"], impact=row["impact"], reproduction=row["reproduction"], evidence=[Evidence(**item) for item in row["evidence"]], structured_scope_id=row.get("structured_scope_id"), weakness_id=row.get("weakness_id"), metadata=row.get("metadata") or {})
        validation = validate_finding(candidate)
        if not validation.ok:
            raise HTTPException(status_code=400, detail="Report completeness check failed: " + "; ".join(validation.blockers))
        api = HackerOneClient(Settings())
        try:
            scopes = normalize_scopes(api.structured_scopes(row["program_handle"]))
            ok, asset, reason = target_is_in_scope(row["target"], scopes)
            if not ok or asset is None or not asset.eligible_for_submission:
                raise HTTPException(status_code=400, detail=f"Current scope check failed: {reason}")
        finally:
            api.close()
        store.set_state(finding_id, "approved")
        return {"status": "approved", "finding": store.get_finding(finding_id)}
    finally:
        store.close()


@app.post("/api/cron/submit-verified-finding")
async def cron_submit_verified_finding(
    request: Request,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    """
    One-shot human-approved submission path for the CI runner.

    This endpoint is intentionally separate from autonomous research. The caller
    must authenticate with CRON_SECRET and provide an explicit human confirmation
    plus the reproduction steps that were personally verified. Current program
    bounty/scope and normal finding validation are re-checked immediately before
    the HackerOne API submission.
    """
    _verify_cron_secret(authorization)
    try:
        body = await request.json()
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid JSON.") from exc
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="Request body must be a JSON object.")

    try:
        finding_id = int(body.get("finding_id"))
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail="finding_id must be an integer.") from exc

    confirmation = str(body.get("confirmation") or "").strip()
    required_confirmation = (
        "I personally reproduced the issue, verified current scope/rules, "
        "checked evidence and duplicates, and approve this report for HackerOne submission."
    )
    if confirmation != required_confirmation:
        raise HTTPException(status_code=400, detail="Explicit human submission confirmation is required.")

    reproduction = body.get("reproduction")
    if not isinstance(reproduction, list) or not all(str(step).strip() for step in reproduction):
        raise HTTPException(status_code=400, detail="Verified reproduction steps are required.")

    from h1_agent.config import Settings
    from h1_agent.hackerone import HackerOneAPIError, HackerOneClient
    from h1_agent.models import Evidence, Finding
    from h1_agent.reporting import markdown_report
    from h1_agent.scope import normalize_scopes, target_is_in_scope
    from h1_agent.store import Store
    from h1_agent.validation import validate_finding

    settings = Settings()
    if not settings.enable_submission:
        raise HTTPException(status_code=403, detail="HackerOne submission is disabled.")

    store = Store(settings)
    try:
        row = store.get_finding(finding_id)
        if row.get("state") == "submitted":
            return {"status": "already_submitted", "finding": row}
        if row.get("state") not in {"draft", "needs_review", "approved"}:
            raise HTTPException(status_code=400, detail=f"Finding state {row.get('state')!r} cannot be submitted.")

        row["reproduction"] = [str(step).strip() for step in reproduction]
        row["state"] = "approved"
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
        validation = validate_finding(finding)
        if not validation.ok:
            raise HTTPException(status_code=400, detail="Report completeness check failed: " + "; ".join(validation.blockers))

        api = HackerOneClient(settings)
        try:
            program_payload = api.program(finding.program_handle)
            attrs = program_payload.get("data", {}).get("attributes", {})
            scopes = normalize_scopes(api.structured_scopes(finding.program_handle))
            ok, asset, reason = target_is_in_scope(finding.target, scopes)
            if not ok or asset is None:
                raise HTTPException(status_code=400, detail=f"Current scope check failed: {reason}")
            if not asset.eligible_for_bounty:
                raise HTTPException(status_code=400, detail="Current asset is not bounty-eligible.")
            if not asset.eligible_for_submission:
                raise HTTPException(status_code=400, detail="Current asset is not eligible for submission.")

            payload = api.create_report(
                team_handle=finding.program_handle,
                title=finding.title,
                vulnerability_information=markdown_report(finding),
                impact=finding.impact,
                severity_rating=finding.severity or "none",
                weakness_id=finding.weakness_id,
                structured_scope_id=(int(finding.structured_scope_id) if str(finding.structured_scope_id or "").isdigit() else None),
            )
        except HackerOneAPIError as exc:
            raise HTTPException(status_code=400, detail=f"HackerOne submission failed: {exc}") from exc
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"Submission preparation failed: {exc.__class__.__name__}: {exc}") from exc
        finally:
            api.close()

        # Persist the exact human-verified reproduction and the submitted H1 response.
        row["reproduction"] = finding.reproduction
        store.set_state(finding_id, "approved")
        store.mark_submitted(finding_id, payload)
        return {"status": "submitted", "finding": store.get_finding(finding_id), "report": payload}
    finally:
        store.close()


@app.post("/api/findings/{finding_id}/submit")
def submit_finding(finding_id: int, request: Request, x_action_token: str | None = Header(default=None)) -> dict[str, Any]:
    _require_session(request)
    _verify_action_token(x_action_token)
    from h1_agent.config import Settings
    from h1_agent.hackerone import HackerOneClient
    from h1_agent.models import Evidence, Finding
    from h1_agent.reporting import markdown_report
    from h1_agent.store import Store
    from h1_agent.validation import require_human_approval
    settings = Settings()
    if not settings.enable_submission:
        raise HTTPException(status_code=403, detail="HackerOne submission is disabled.")
    store = Store(settings)
    try:
        row = store.get_finding(finding_id)
        if row.get("state") != "approved":
            raise HTTPException(status_code=400, detail="Only an approved finding can be submitted.")
        finding = Finding(program_handle=row["program_handle"], target=row["target"], title=row["title"], severity=row.get("severity"), state="approved", summary=row["summary"], impact=row["impact"], reproduction=row["reproduction"], evidence=[Evidence(**item) for item in row["evidence"]], structured_scope_id=row.get("structured_scope_id"), weakness_id=row.get("weakness_id"), metadata=row.get("metadata") or {})
        try:
            require_human_approval(finding)
        except (ValueError, PermissionError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        api = HackerOneClient(settings)
        try:
            payload = api.create_report(team_handle=finding.program_handle, title=finding.title, vulnerability_information=markdown_report(finding), impact=finding.impact, severity_rating=finding.severity or "none", weakness_id=finding.weakness_id, structured_scope_id=(int(finding.structured_scope_id) if str(finding.structured_scope_id or "").isdigit() else None))
        finally:
            api.close()
        store.mark_submitted(finding_id, payload)
        return {"status": "submitted", "report": payload}
    finally:
        store.close()


@app.get("/api/capabilities")
def capabilities(request: Request) -> dict[str, Any]:
    _require_session(request)
    return {"capabilities": [], "human_validation_required": True}


@app.get("/api/programs")
def programs(request: Request) -> dict[str, Any]:
    _require_session(request)
    from h1_agent.config import Settings
    from h1_agent.hackerone import HackerOneClient
    settings = Settings()
    api = HackerOneClient(settings)
    try:
        return api.programs(page=1, page_size=25)
    finally:
        api.close()


def _run_autonomous_research_background(job_id: str) -> None:
    _run_research_job_background(job_id, [], "full")


def _run_research_job_background(job_id: str, programs: list[str], mode: str) -> None:
    from h1_agent.config import Settings
    from h1_agent.store import Store
    from h1_agent.worker import run_cycle
    settings = Settings()
    store = Store(settings)
    try:
        def progress(payload: dict) -> None:
            store.update_research_job(job_id, {"status": "running", "progress": payload})
        store.update_research_job(job_id, {"status": "running", "progress": {"program": None, "target": None, "completed_targets": 0, "planned_targets": 0}})
        result = run_cycle(settings, requested_programs=set(programs), mode=mode, on_progress=progress)
        job_error = result.get("error")
        if not job_error and result.get("status") == "error":
            failures = [f"{item.get('program')}: {item.get('error')}" for item in result.get("program_results", []) if item.get("error")]
            job_error = " | ".join(failures) if failures else "Research job failed without a reported error."
        store.update_research_job(job_id, {"status": "completed" if result.get("status") in {"ok", "blocked"} else "error", "result": result, "error": job_error, "progress": {"program": None, "target": None, "completed_targets": result.get("researched_targets", 0), "planned_targets": result.get("researched_targets", 0)}})
    except Exception as exc:
        try:
            store.update_research_job(job_id, {"status": "error", "error": f"{exc.__class__.__name__}: {exc}"})
        except Exception:
            pass
    finally:
        store.close()


@app.post("/api/discovery/jobs")
async def start_discovery_job(request: Request, background_tasks: BackgroundTasks, x_action_token: str | None = Header(default=None)) -> JSONResponse:
    _require_session(request)
    _verify_action_token(x_action_token)
    from h1_agent.config import Settings
    from h1_agent.store import Store
    store = Store(Settings())
    try:
        job_id = store.create_research_job({"programs": [], "mode": "discovery"})
    finally:
        store.close()
    background_tasks.add_task(_run_research_job_background, job_id, [], "discovery")
    return JSONResponse(status_code=202, content={"status": "queued", "job_id": job_id, "mode": "discovery"})


@app.get("/api/discovery/jobs/{job_id}")
def get_discovery_job(job_id: str, request: Request) -> dict[str, Any]:
    _require_session(request)
    from h1_agent.config import Settings
    from h1_agent.store import Store
    store = Store(Settings())
    try:
        result = store.get_research_job(job_id)
        if result.get("mode") != "discovery":
            raise HTTPException(status_code=400, detail="Job is not a discovery job.")
        return result
    finally:
        store.close()


@app.post("/api/research/jobs")
async def start_research_job(request: Request, background_tasks: BackgroundTasks, x_action_token: str | None = Header(default=None)) -> JSONResponse:
    _require_session(request)
    _verify_action_token(x_action_token)
    try:
        parsed = await request.json()
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid JSON.") from exc
    if not isinstance(parsed, dict):
        raise HTTPException(status_code=400, detail="Request body must be a JSON object.")
    programs = sorted({str(handle).strip() for handle in parsed.get("programs", []) if str(handle).strip()})
    mode = str(parsed.get("mode", "full") or "full").strip().lower()
    if not programs:
        raise HTTPException(status_code=400, detail="At least one program handle is required.")
    if mode not in {"full", "deep", "deep-research"}:
        raise HTTPException(status_code=400, detail="This endpoint only starts full/deep research.")
    from h1_agent.config import Settings
    from h1_agent.store import Store
    store = Store(Settings())
    try:
        job_id = store.create_research_job({"programs": programs, "mode": mode})
    finally:
        store.close()
    background_tasks.add_task(_run_research_job_background, job_id, programs, mode)
    return JSONResponse(status_code=202, content={"status": "queued", "job_id": job_id, "mode": "full", "programs": programs})


@app.get("/api/research/jobs/{job_id}")
def get_research_job(job_id: str, request: Request) -> dict[str, Any]:
    _require_session(request)
    from h1_agent.config import Settings
    from h1_agent.store import Store
    store = Store(Settings())
    try:
        result = store.get_research_job(job_id)
        if result.get("status") == "error" and not result.get("error"):
            payload = result.get("result") or {}
            failures = [f"{item.get('program')}: {item.get('error')}" for item in payload.get("program_results", []) if item.get("error")]
            result["error"] = payload.get("error") or (" | ".join(failures) if failures else "Research job failed without a reported error.")
        return result
    finally:
        store.close()


@app.post("/api/worker")
async def worker(request: Request, background_tasks: BackgroundTasks, x_action_token: str | None = Header(default=None)) -> JSONResponse:
    _require_session(request)
    _verify_action_token(x_action_token)
    body: dict[str, Any] = {}
    try:
        parsed = await request.json()
        if isinstance(parsed, dict):
            body = parsed
    except Exception:
        body = {}
    requested_programs = sorted({str(handle).strip() for handle in body.get("programs", []) if str(handle).strip()})
    active = bool(body.get("active", False))
    mode = str(body.get("mode", "") or "").strip().lower()
    if requested_programs:
        job_mode = mode if mode in {"full", "deep", "deep-research", "active", "assessment", "passive"} else "full"
        programs_for_job = requested_programs
    else:
        job_mode = "discovery"
        programs_for_job = []
    from h1_agent.config import Settings
    from h1_agent.store import Store
    store = Store(Settings())
    try:
        job_id = store.create_research_job({"programs": programs_for_job, "mode": job_mode})
    finally:
        store.close()
    background_tasks.add_task(_run_research_job_background, job_id, programs_for_job, "active" if active and job_mode == "active" else job_mode)
    return JSONResponse(status_code=202, content={"status": "queued", "job_id": job_id, "mode": job_mode, "programs": programs_for_job})


@app.get("/api/cron/files-authz-probe")
def files_authz_probe(authorization: str | None = Header(default=None)) -> dict[str, Any]:
    """Bounded authorization test against the researcher's Files.com BUGBOUNTY trial.

    Uses only credentials already stored in the private deployment environment.
    Never returns credential values or response bodies.
    """
    _verify_cron_secret(authorization)

    enabled = os.getenv("FILES_AUTHZ_TRIAL_PROBE", "").strip().lower() == "true"
    if not enabled:
        return {"status": "disabled", "reason": "FILES_AUTHZ_TRIAL_PROBE is not enabled"}

    base = os.getenv("FILES_BASE_URL", "").strip().rstrip("/")
    raw_a = os.getenv("AUTHZ_HEADER_A", "").strip()
    raw_b = os.getenv("AUTHZ_HEADER_B", "").strip()

    if not base:
        return {"status": "skipped", "reason": "FILES_BASE_URL is not configured"}
    if not raw_a:
        return {"status": "skipped", "reason": "AUTHZ_HEADER_A is not configured"}

    import httpx
    from urllib.parse import urlparse

    def parse_header(raw: str) -> tuple[str, str]:
        name, value = raw.split(":", 1)
        return name.strip(), value.strip()

    def redact_header_name(raw: str) -> str:
        try:
            return parse_header(raw)[0]
        except Exception:
            return "invalid"

    header_a_name, header_a_value = parse_header(raw_a)
    header_b = None
    if raw_b:
        try:
            header_b = parse_header(raw_b)
        except Exception:
            header_b = None

    def request(client: httpx.Client, method: str, path: str, headers: tuple[str, str], payload: dict[str, Any] | None = None):
        hname, hvalue = headers
        response = client.request(
            method,
            f"{base}{path}",
            headers={hname: hvalue, "Accept": "application/json"},
            json=payload,
            follow_redirects=False,
        )
        body = response.content
        return {
            "status": response.status_code,
            "bytes": len(body),
            "sha256": hashlib.sha256(body).hexdigest() if body else "",
            "content_type": response.headers.get("content-type", ""),
            "location": response.headers.get("location", ""),
        }, response

    target_origin = f"{urlparse(base).scheme}://{urlparse(base).netloc}"
    results: dict[str, Any] = {
        "status": "ok",
        "target_origin": target_origin,
        "authorization_header_a": redact_header_name(raw_a),
        "authorization_header_b": redact_header_name(raw_b) if raw_b else None,
        "checks": [],
        "candidate": None,
        "escalation": None,
    }

    with httpx.Client(timeout=15.0, headers={"User-Agent": "H1-Bounty-Agent/FilesCom-AuthzProbe/1.0"}) as client:
        before_meta, before_resp = request(client, "GET", "/api/rest/v1/api_key.json", (header_a_name, header_a_value))
        before_json: dict[str, Any] = {}
        try:
            parsed = before_resp.json()
            if isinstance(parsed, dict):
                before_json = parsed
        except Exception:
            pass

        permission_set = str(before_json.get("permission_set") or "")
        key_name = str(before_json.get("name") or "")
        key_url = str(before_json.get("url") or "")
        results["key_permission_set"] = permission_set
        results["key_is_marked_bugbounty"] = "BUGBOUNTY" in key_name.upper()
        results["key_url_matches_target"] = bool(key_url) and (
            f"{urlparse(key_url).scheme}://{urlparse(key_url).netloc}" == target_origin
        )

        results["checks"].append({
            "endpoint": "/api/rest/v1/api_key.json",
            "method": "GET",
            **before_meta,
        })

        if before_meta["status"] != 200 or permission_set != "files_only" or not results["key_is_marked_bugbounty"] or not results["key_url_matches_target"]:
            results["status"] = "stopped"
            results["reason"] = "The configured credential did not validate as the expected BUGBOUNTY files_only key for the configured trial."
            return results

        protected = [
            "/api/rest/v1/permissions.json?per_page=1",
            "/api/rest/v1/users.json?per_page=1",
            "/api/rest/v1/api_keys.json?per_page=1",
            "/api/rest/v1/workspaces.json?per_page=1",
            "/api/rest/v1/public_keys.json?per_page=1",
            "/api/rest/v1/custom_domains.json?per_page=1",
            "/api/rest/v1/event_targets.json?per_page=1",
            "/api/rest/v1/user_lifecycle_rules.json?per_page=1",
            "/api/rest/v1/history.json?per_page=1",
            "/api/rest/v1/sso_events.json?per_page=1",
        ]

        for path in protected:
            meta, _ = request(client, "GET", path, (header_a_name, header_a_value))
            results["checks"].append({"endpoint": path, "method": "GET", **meta})
            if 200 <= meta["status"] < 300 and meta["bytes"] > 0:
                results["candidate"] = {
                    "type": "files_only_authorization_boundary",
                    "endpoint": path,
                    "method": "GET",
                    "status": meta["status"],
                    "bytes": meta["bytes"],
                    "sha256": meta["sha256"],
                    "content_type": meta["content_type"],
                }
                break

        if results["candidate"] is None and os.getenv("FILES_AUTHZ_ESCALATION_TEST", "").strip().lower() == "true":
            payload = {"permission_set": "full", "name": "BUGBOUNTY-AUTHZ-ESCALATION-TEST"}
            patch_meta, patch_resp = request(client, "PATCH", "/api/rest/v1/api_key.json", (header_a_name, header_a_value), payload)
            after_permission = ""
            try:
                parsed = patch_resp.json()
                if isinstance(parsed, dict):
                    after_permission = str(parsed.get("permission_set") or "")
            except Exception:
                pass

            restore_meta = None
            if 200 <= patch_meta["status"] < 300:
                restore_payload = {"permission_set": "files_only", "name": key_name}
                restore_meta, _ = request(client, "PATCH", "/api/rest/v1/api_key.json", (header_a_name, header_a_value), restore_payload)

            results["escalation"] = {
                "attempted": True,
                "patch": patch_meta,
                "returned_permission_set": after_permission,
                "restore": restore_meta,
            }

            if 200 <= patch_meta["status"] < 300 and after_permission == "full":
                results["candidate"] = {
                    "type": "files_only_self_escalation",
                    "endpoint": "/api/rest/v1/api_key.json",
                    "method": "PATCH",
                    "status": patch_meta["status"],
                    "returned_permission_set": after_permission,
                    "restore_status": (restore_meta or {}).get("status"),
                }

        if header_b and results["candidate"] is None:
            bola_targets = [
                "/api/rest/v1/users.json?per_page=1",
                "/api/rest/v1/permissions.json?per_page=1",
            ]
            for path in bola_targets:
                meta_a, resp_a = request(client, "GET", path, (header_a_name, header_a_value))
                meta_b, resp_b = request(client, "GET", path, header_b)
                results["checks"].append({
                    "endpoint": path,
                    "method": "GET",
                    "account_a": meta_a,
                    "account_b": meta_b,
                })
                if 200 <= meta_a["status"] < 300 and 200 <= meta_b["status"] < 300:
                    results["possible_two_account_overlap"] = True

    return results


@app.get("/api/diagnostics")
def diagnostics(request: Request) -> dict[str, Any]:
    _require_session(request)
    from h1_agent.config import Settings
    settings = Settings()
    result: dict[str, Any] = {"hackerone_username_configured": bool(settings.hackerone_username), "hackerone_token_configured": bool(settings.hackerone_api_token), "hackerone_base_url": settings.hackerone_base_url, "requests_per_second": settings.requests_per_second, "dry_run": settings.dry_run, "allow_active_tests": settings.allow_active_tests, "autonomous_research": settings.autonomous_research, "autonomous_passive_research": settings.autonomous_passive_research, "submission_enabled": settings.enable_submission}
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
def cron(
    background_tasks: BackgroundTasks,
    authorization: str | None = Header(default=None),
    x_h1_sync: str | None = Header(default=None),
) -> dict[str, Any]:
    _verify_cron_secret(authorization)
    from h1_agent.config import Settings
    from h1_agent.store import Store
    settings = Settings()
    store = Store(settings)
    try:
        queued = store.claim_next_research_job()
        if queued:
            job_id = str(queued["id"])
            programs = [str(item) for item in queued.get("programs", [])]
            mode = str(queued.get("mode") or "full")
            if x_h1_sync == "1":
                _run_research_job_background(job_id, programs, mode)
                return store.get_research_job(job_id)
            background_tasks.add_task(_run_research_job_background, job_id, programs, mode)
            return {"status": "accepted", "mode": "queued-job", "job_id": job_id}
        if settings.autonomous_research:
            job_id = store.create_research_job({"programs": [], "mode": "full", "source": "autonomous-cron"})
            if x_h1_sync == "1":
                _run_autonomous_research_background(job_id)
                return store.get_research_job(job_id)
            background_tasks.add_task(_run_autonomous_research_background, job_id)
            return {"status": "accepted", "mode": "autonomous-hunt", "job_id": str(job_id)}
        return {"status": "idle", "mode": "no-queued-job"}
    finally:
        store.close()
