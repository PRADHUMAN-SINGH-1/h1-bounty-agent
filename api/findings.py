from __future__ import annotations

from fastapi import Depends, FastAPI, Header
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from h1_agent.config import Settings
from h1_agent.hackerone import HackerOneClient
from h1_agent.reporting import markdown_report
from h1_agent.scope import normalize_scopes, target_is_in_scope
from h1_agent.store import Store
from h1_agent.web_auth import require_basic, verify_action_token

app = FastAPI(title="H1 Findings API", version="0.4.0")
basic = HTTPBasic(auto_error=False)


def _auth(credentials: HTTPBasicCredentials | None = Depends(basic)) -> None:
    settings = Settings()
    require_basic(credentials, settings.dashboard_user, settings.dashboard_password)


def _verify_current_scope(api: HackerOneClient, program_handle: str, target: str) -> None:
    scopes = normalize_scopes(api.structured_scopes(program_handle))
    ok, asset, reason = target_is_in_scope(target, scopes)
    if not ok or asset is None:
        raise ValueError(f"Current HackerOne scope check failed: {reason}")
    if not asset.eligible_for_submission:
        raise ValueError("Current HackerOne scope marks this asset as not eligible for submission.")


@app.get("/", dependencies=[Depends(_auth)])
def list_findings() -> dict:
    settings = Settings()
    store = Store(settings)
    try:
        return {"findings": store.list_findings(), "durable_storage": store.durable, "action_token": __import__("h1_agent.web_auth", fromlist=["action_token"]).action_token(settings.dashboard_secret)}
    finally:
        store.close()


@app.get("/{finding_id}", dependencies=[Depends(_auth)])
def get_finding(finding_id: int) -> dict:
    settings = Settings()
    store = Store(settings)
    try:
        return store.get_finding(finding_id)
    finally:
        store.close()


@app.post("/{finding_id}/approve", dependencies=[Depends(_auth)])
def approve_finding(
    finding_id: int,
    x_action_token: str | None = Header(default=None),
) -> dict:
    settings = Settings()
    verify_action_token(x_action_token, settings.dashboard_secret)

    store = Store(settings)
    api = HackerOneClient(settings)
    try:
        finding = store.get_finding(finding_id)
        if finding["state"] not in {"needs_review", "draft"}:
            return {"status": "unchanged", "finding": finding}

        for key in ("title", "summary", "impact"):
            if not finding.get(key):
                raise ValueError(f"Finding is incomplete: missing {key}.")
        if not finding.get("evidence") or not finding.get("reproduction"):
            raise ValueError("Finding is incomplete: evidence and reproduction are required.")

        _verify_current_scope(api, finding["program_handle"], finding["target"])
        store.set_state(finding_id, "approved")
        return {"status": "approved", "finding": store.get_finding(finding_id)}
    finally:
        api.close()
        store.close()


@app.post("/{finding_id}/submit", dependencies=[Depends(_auth)])
def submit_finding(
    finding_id: int,
    x_action_token: str | None = Header(default=None),
) -> dict:
    settings = Settings()
    verify_action_token(x_action_token, settings.dashboard_secret)
    settings.require_submission_enabled()

    store = Store(settings)
    api = HackerOneClient(settings)
    try:
        finding = store.get_finding(finding_id)
        if finding["state"] != "approved":
            raise ValueError("Only an explicitly approved finding can be submitted.")
        severity = str(finding.get("severity") or "").lower()
        if severity not in {"none", "low", "medium", "high", "critical"}:
            raise ValueError("Finding severity must be set before submission.")

        _verify_current_scope(api, finding["program_handle"], finding["target"])

        evidence = [
            type("EvidenceView", (), item)()
            for item in finding["evidence"]
        ]
        finding_view = type(
            "FindingView",
            (),
            {
                "title": finding["title"],
                "summary": finding["summary"],
                "impact": finding["impact"],
                "reproduction": finding["reproduction"],
                "evidence": evidence,
                "severity": severity,
                "program_handle": finding["program_handle"],
                "target": finding["target"],
            },
        )()

        payload = api.create_report(
            team_handle=finding["program_handle"],
            title=finding["title"],
            vulnerability_information=markdown_report(finding_view),
            impact=finding["impact"],
            severity_rating=severity,
            weakness_id=finding.get("weakness_id"),
            structured_scope_id=(
                int(finding["structured_scope_id"])
                if str(finding.get("structured_scope_id") or "").isdigit()
                else None
            ),
        )
        store.mark_submitted(finding_id, payload)
        return {"status": "submitted", "report": payload}
    finally:
        api.close()
        store.close()
