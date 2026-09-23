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


@app.get("/", include_in_schema=False)
def dashboard() -> FileResponse:
    path = Path(__file__).resolve().parent.parent / "public" / "index.html"
    if not path.exists():
        raise HTTPException(status_code=404, detail="Dashboard not found.")
    return FileResponse(path, media_type="text/html")


@app.get("/healthz", include_in_schema=False)
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api")
def health() -> dict[str, Any]:
    return {
        "service": "h1-bounty-agent",
        "status": "online",
        "version": "0.8.0",
        "dry_run": os.getenv("DRY_RUN", "true"),
        "active_tests": os.getenv("ALLOW_ACTIVE_TESTS", "false"),
        "autonomous_research": os.getenv("AUTONOMOUS_RESEARCH", "false"),
        "autonomous_passive_research": os.getenv("AUTONOMOUS_PASSIVE_RESEARCH", "false"),
        "submission_enabled": os.getenv("H1_ENABLE_SUBMISSION", "false"),
    }


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
            # Keep the dashboard responsive while surfacing the actual backend failure.
            rows = []
            storage_error = f"{exc.__class__.__name__}: {exc}"
        return {
            "findings": rows,
            "durable_storage": store.durable,
            "action_token": _action_token(),
            "storage_error": storage_error,
        }
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


@app.post("/api/findings/{finding_id}/approve")
def approve_finding(
    finding_id: int,
    request: Request,
    x_action_token: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_session(request)
    _verify_action_token(x_action_token)

    from h1_agent.config import Settings
    from h1_agent.hackerone import HackerOneClient
    from h1_agent.models import Evidence, Finding
    from h1_agent.scope import normalize_scopes, target_is_in_scope
    from h1_agent.store import Store
    from h1_agent.validation import validate_finding

    store = Store(Settings())
    try:
        try:
            row = store.get_finding(finding_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="Finding not found.") from exc

        for key in ("title", "summary", "impact", "evidence", "reproduction"):
            if not row.get(key):
                raise HTTPException(status_code=400, detail=f"Finding is incomplete: {key}.")

        candidate = Finding(
            program_handle=row["program_handle"],
            target=row["target"],
            title=row["title"],
            severity=row.get("severity"),
            state=row.get("state", "needs_review"),
            summary=row["summary"],
            impact=row["impact"],
            reproduction=row["reproduction"],
            evidence=[Evidence(**item) for item in row["evidence"]],
            structured_scope_id=row.get("structured_scope_id"),
            weakness_id=row.get("weakness_id"),
            metadata=row.get("metadata") or {},
        )
        validation = validate_finding(candidate)
        if not validation.ok:
            raise HTTPException(
                status_code=400,
                detail="Report completeness check failed: " + "; ".join(validation.blockers),
            )

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


@app.post("/api/findings/{finding_id}/submit")
def submit_finding(
    finding_id: int,
    request: Request,
    x_action_token: str | None = Header(default=None),
) -> dict[str, Any]:
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
        try:
            row = store.get_finding(finding_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="Finding not found.") from exc
        if row.get("state") != "approved":
            raise HTTPException(status_code=400, detail="Only an approved finding can be submitted.")

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

        store.mark_submitted(finding_id, payload)
        return {"status": "submitted", "report": payload}
    finally:
        store.close()


@app.get("/api/capabilities")
def capabilities(request: Request) -> dict[str, Any]:
    _require_session(request)
    return {
        "capabilities": [
            {"name": "Authenticated session mapping", "status": "implemented", "requires": "Authorized session header"},
            {"name": "Read-only workflow exploration", "status": "implemented", "requires": "In-scope target"},
            {"name": "IDOR / BOLA differential testing", "status": "implemented", "requires": "Two authorized test accounts"},
            {"name": "Role / permission differential modeling", "status": "implemented", "requires": "Two authorized test accounts"},
            {"name": "Stateful read-only API workflows", "status": "implemented", "requires": "OpenAPI or discovered API operations"},
            {"name": "GraphQL introspection", "status": "implemented", "requires": "In-scope GraphQL endpoint"},
            {"name": "WebSocket discovery / handshake", "status": "implemented", "requires": "In-scope WebSocket endpoint"},
            {"name": "Mobile package static analysis", "status": "implemented", "requires": "APK/IPA artifact for local analysis"},
            {"name": "Cloud / IAM footprint analysis", "status": "implemented", "requires": "Cloud references or policy text"},
            {"name": "Attack-chain correlation", "status": "implemented", "requires": "Multiple evidence classes"},
            {"name": "Durable background research runner", "status": "implemented", "requires": "GitHub Actions runner + Postgres queue"},
            {"name": "Open-source recon toolchain", "status": "implemented", "requires": "subfinder/httpx/katana/nuclei/gau/waybackurls"},

            {"name": "Deep business-logic / workflow modeling", "status": "implemented", "requires": "Observed authorized application workflow"},
            {"name": "Browser/session trace understanding", "status": "implemented", "requires": "Authorized HAR/browser trace"},
            {"name": "Object ownership model", "status": "implemented", "requires": "Observed object identifiers plus authorized accounts"},
            {"name": "Role / privilege graph", "status": "implemented", "requires": "Two authorized account observations"},
            {"name": "State-change mutation planning", "status": "implemented", "requires": "Observed state-changing requests; execution separately gated"},
            {"name": "Controlled state-changing validation", "status": "implemented", "requires": "Explicit ALLOW_STATE_CHANGING_TESTS + program authorization"},
            {"name": "Attack hypothesis generation", "status": "implemented", "requires": "Application-model evidence"},
            {"name": "Attack-chain hypothesis correlation", "status": "implemented", "requires": "Multiple evidence classes"},
            {"name": "Recon change detection", "status": "implemented", "requires": "Previous stored surface snapshot"},
            {"name": "Persistent research memory", "status": "implemented", "requires": "Research run state"},
            {"name": "Human feedback / validation loop", "status": "implemented", "requires": "Dashboard approval + reproduced evidence"},
        ],
        "human_validation_required": True,
    }


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


def _run_autonomous_research_background() -> None:
    from h1_agent.config import Settings
    from h1_agent.store import Store
    from h1_agent.worker import run_cycle

    settings = Settings()
    store = Store(settings)
    try:
        result = run_cycle(settings, mode="full")
        # Scheduled autonomous runs are durable through their findings/results.
        if result.get("status") == "error":
            return
    finally:
        store.close()


def _run_research_job_background(job_id: str, programs: list[str], mode: str) -> None:
    from h1_agent.config import Settings
    from h1_agent.store import Store
    from h1_agent.worker import run_cycle

    settings = Settings()
    store = Store(settings)
    try:
        def progress(payload: dict) -> None:
            store.update_research_job(
                job_id,
                {"status": "running", "progress": payload},
            )

        store.update_research_job(
            job_id,
            {
                "status": "running",
                "progress": {
                    "program": None,
                    "target": None,
                    "completed_targets": 0,
                    "planned_targets": 0,
                },
            },
        )
        result = run_cycle(
            settings,
            requested_programs=set(programs),
            mode=mode,
            on_progress=progress,
        )
        job_error = result.get("error")
        if not job_error and result.get("status") == "error":
            failures = [
                f"{item.get('program')}: {item.get('error')}"
                for item in result.get("program_results", [])
                if item.get("error")
            ]
            job_error = " | ".join(failures) if failures else "Research job failed without a reported error."
        store.update_research_job(
            job_id,
            {
                "status": "completed" if result.get("status") in {"ok", "blocked"} else "error",
                "result": result,
                "error": job_error,
                "progress": {
                    "program": None,
                    "target": None,
                    "completed_targets": result.get("researched_targets", 0),
                    "planned_targets": result.get("researched_targets", 0),
                },
            },
        )
    except Exception as exc:
        error_text = f"{exc.__class__.__name__}: {exc}"
        try:
            store.update_research_job(
                job_id,
                {
                    "status": "error",
                    "error": error_text,
                },
            )
        except Exception:
            pass
    finally:
        store.close()


@app.post("/api/discovery/jobs")
async def start_discovery_job(
    request: Request,
    background_tasks: BackgroundTasks,
    x_action_token: str | None = Header(default=None),
) -> JSONResponse:
    _require_session(request)
    _verify_action_token(x_action_token)

    from h1_agent.config import Settings
    from h1_agent.store import Store

    store = Store(Settings())
    try:
        job_id = store.create_research_job({"programs": [], "mode": "discovery"})
    finally:
        store.close()

    background_tasks.add_task(
        _run_research_job_background,
        job_id,
        [],
        "discovery",
    )

    return JSONResponse(
        status_code=202,
        content={
            "status": "queued",
            "job_id": job_id,
            "mode": "discovery",
        },
    )


@app.get("/api/discovery/jobs/{job_id}")
def get_discovery_job(job_id: str, request: Request) -> dict[str, Any]:
    _require_session(request)
    from h1_agent.config import Settings
    from h1_agent.store import Store

    store = Store(Settings())
    try:
        try:
            result = store.get_research_job(job_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        if result.get("mode") != "discovery":
            raise HTTPException(status_code=400, detail="Job is not a discovery job.")
        return result
    finally:
        store.close()


@app.post("/api/research/jobs")
async def start_research_job(
    request: Request,
    background_tasks: BackgroundTasks,
    x_action_token: str | None = Header(default=None),
) -> JSONResponse:
    _require_session(request)
    _verify_action_token(x_action_token)
    try:
        parsed = await request.json()
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid JSON.") from exc
    if not isinstance(parsed, dict):
        raise HTTPException(status_code=400, detail="Request body must be a JSON object.")
    body = parsed

    programs = sorted({
        str(handle).strip()
        for handle in body.get("programs", [])
        if str(handle).strip()
    })
    mode = str(body.get("mode", "full") or "full").strip().lower()
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

    background_tasks.add_task(
        _run_research_job_background,
        job_id,
        programs,
        mode,
    )

    return JSONResponse(
        status_code=202,
        content={
            "status": "queued",
            "job_id": job_id,
            "mode": "full",
            "programs": programs,
        },
    )


@app.get("/api/research/jobs/{job_id}")
def get_research_job(job_id: str, request: Request) -> dict[str, Any]:
    _require_session(request)
    from h1_agent.config import Settings
    from h1_agent.store import Store

    store = Store(Settings())
    try:
        try:
            result = store.get_research_job(job_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        if result.get("status") == "error" and not result.get("error"):
            payload = result.get("result") or {}
            failures = [
                f"{item.get('program')}: {item.get('error')}"
                for item in payload.get("program_results", [])
                if item.get("error")
            ]
            result["error"] = payload.get("error") or (
                " | ".join(failures) if failures else "Research job failed without a reported error."
            )
        return result
    finally:
        store.close()


@app.post("/api/worker")
async def worker(
    request: Request,
    background_tasks: BackgroundTasks,
    x_action_token: str | None = Header(default=None),
) -> JSONResponse:
    """Compatibility endpoint that always queues work; it never executes a long cycle in the request."""
    _require_session(request)
    _verify_action_token(x_action_token)

    body: dict[str, Any] = {}
    try:
        parsed = await request.json()
        if isinstance(parsed, dict):
            body = parsed
    except Exception:
        body = {}

    requested_programs = sorted({
        str(handle).strip()
        for handle in body.get("programs", [])
        if str(handle).strip()
    })
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

    background_tasks.add_task(
        _run_research_job_background,
        job_id,
        programs_for_job,
        "active" if active and job_mode == "active" else job_mode,
    )
    return JSONResponse(
        status_code=202,
        content={
            "status": "queued",
            "job_id": job_id,
            "mode": job_mode,
            "programs": programs_for_job,
        },
    )



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
def cron(
    background_tasks: BackgroundTasks,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    secret = os.getenv("CRON_SECRET", "")
    if not secret:
        raise HTTPException(status_code=503, detail="CRON_SECRET is not configured.")
    if authorization != f"Bearer {secret}":
        raise HTTPException(status_code=401, detail="Unauthorized")

    from h1_agent.config import Settings
    from h1_agent.store import Store

    settings = Settings()
    store = Store(settings)
    try:
        queued = store.claim_next_research_job()
    finally:
        store.close()

    if queued:
        background_tasks.add_task(
            _run_research_job_background,
            str(queued["id"]),
            [str(item) for item in queued.get("programs", [])],
            str(queued.get("mode") or "full"),
        )
        return {
            "status": "accepted",
            "mode": "queued-job",
            "job_id": str(queued["id"]),
        }

    if settings.autonomous_research:
        background_tasks.add_task(_run_autonomous_research_background)
        return {"status": "accepted", "mode": "autonomous-hunt"}

    return {
        "status": "idle",
        "mode": "no-queued-job",
    }
