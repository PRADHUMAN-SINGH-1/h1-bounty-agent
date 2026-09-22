from __future__ import annotations

from fastapi import Depends, FastAPI, Header
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from h1_agent.config import Settings
from h1_agent.hackerone import HackerOneClient
from h1_agent.reporting import markdown_report
from h1_agent.store import Store
from h1_agent.web_auth import require_basic, verify_action_token

app = FastAPI(title="H1 Findings API", version="0.4.0")
basic = HTTPBasic(auto_error=False)


def _auth(credentials: HTTPBasicCredentials | None = Depends(basic)) -> None:
    settings = Settings()
    require_basic(credentials, settings.dashboard_user, settings.dashboard_password)


@app.get("/", dependencies=[Depends(_auth)])
def list_findings() -> dict:
    settings = Settings()
    store = Store(settings)
    try:
        return {"findings": store.list_findings(), "durable_storage": store.durable}
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
    try:
        finding = store.get_finding(finding_id)
        if finding["state"] not in {"needs_review", "draft"}:
            return {"status": "unchanged", "finding": finding}
        if not finding.get("title") or not finding.get("summary") or not finding.get("impact"):
            raise ValueError("Finding is incomplete.")
        if not finding.get("evidence") or not finding.get("reproduction"):
            raise ValueError("Human review cannot approve a finding without evidence and reproduction.")
        store.set_state(finding_id, "approved")
        return {"status": "approved", "finding": store.get_finding(finding_id)}
    finally:
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

        payload = api.create_report(
            team_handle=finding["program_handle"],
            title=finding["title"],
            vulnerability_information=markdown_report(
                type(
                    "FindingView",
                    (),
                    {
                        "title": finding["title"],
                        "summary": finding["summary"],
                        "impact": finding["impact"],
                        "reproduction": finding["reproduction"],
                        "evidence": [
                            type("EvidenceView", (), item)()
                            for item in finding["evidence"]
                        ],
                        "severity": finding["severity"],
                        "program_handle": finding["program_handle"],
                        "target": finding["target"],
                    },
                )()
            ),
            impact=finding["impact"],
            severity_rating=finding["severity"] or "none",
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
