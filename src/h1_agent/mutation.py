from __future__ import annotations

import json
from dataclasses import dataclass
from urllib.parse import urlparse

import httpx

from .models import Evidence
from .scope import target_is_in_scope


@dataclass(frozen=True)
class MutationPlan:
    method: str
    url: str
    rationale: str
    payload: dict
    requires_confirmation: bool = True


SAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def build_mutation_plans(requests: list[dict], scopes) -> list[MutationPlan]:
    plans = []
    for item in requests[:100]:
        method = str(item.get("method") or "GET").upper()
        url = str(item.get("url") or "")
        if method not in SAFE_METHODS or not target_is_in_scope(url, scopes)[0]:
            continue
        parsed = urlparse(url)
        rationale = "Observed state-changing operation; verify role, ownership, workflow-state and replay invariants before executing."
        payload = {}
        raw_payload = item.get("postData")
        if isinstance(raw_payload, dict) and isinstance(raw_payload.get("text"), str):
            try:
                parsed_payload = json.loads(raw_payload["text"])
                if isinstance(parsed_payload, dict):
                    payload = parsed_payload
            except (TypeError, ValueError):
                pass
        plans.append(MutationPlan(method, url, rationale, payload, True))
    return plans[:50]


class AuthorizedMutationRunner:
    """Bounded mutation executor. Disabled unless the caller explicitly enables it."""

    def __init__(self, client: httpx.Client, allow: bool, max_requests: int = 3):
        self.client = client
        self.allow = allow
        self.max_requests = max(1, max_requests)

    def execute(self, plans: list[MutationPlan], scopes, headers: dict[str, str] | None = None) -> list[Evidence]:
        if not self.allow:
            raise PermissionError(
                "State-changing testing is disabled. Enable the explicit program-approved mutation gate first."
            )
        evidence = []
        for plan in plans[: self.max_requests]:
            if not target_is_in_scope(plan.url, scopes)[0]:
                continue
            if plan.method not in SAFE_METHODS:
                continue
            request_kwargs = {"headers": headers or {}, "follow_redirects": False}
            if plan.payload:
                request_kwargs["json"] = plan.payload
            response = self.client.request(plan.method, plan.url, **request_kwargs)
            evidence.extend(
                [
                    Evidence("mutation_method", plan.method, plan.url),
                    Evidence("mutation_status", str(response.status_code), plan.url),
                    Evidence("mutation_content_type", response.headers.get("content-type", ""), plan.url),
                ]
            )
        return evidence
