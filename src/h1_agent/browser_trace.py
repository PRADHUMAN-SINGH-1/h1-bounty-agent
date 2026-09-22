from __future__ import annotations

import json
from dataclasses import dataclass, asdict
from pathlib import Path
from urllib.parse import urlparse

from .models import Evidence
from .scope import target_is_in_scope


@dataclass(frozen=True)
class BrowserRequest:
    method: str
    url: str
    status: int | None
    resource_type: str
    request_headers: tuple[str, ...]
    response_headers: tuple[str, ...]
    cookies_seen: int
    source: str


@dataclass(frozen=True)
class BrowserSessionModel:
    requests: list[BrowserRequest]
    origins: list[str]
    paths: list[str]
    methods: list[str]
    stateful_signals: list[str]


def _headers(raw: object) -> tuple[str, ...]:
    if not isinstance(raw, list):
        return ()
    result = []
    for item in raw:
        if isinstance(item, dict) and item.get("name"):
            result.append(str(item["name"]).lower())
    return tuple(sorted(set(result)))


def parse_har(payload: dict, scopes) -> tuple[BrowserSessionModel, list[Evidence]]:
    log = payload.get("log") if isinstance(payload, dict) else None
    entries = log.get("entries", []) if isinstance(log, dict) else []
    requests: list[BrowserRequest] = []
    evidence: list[Evidence] = []

    for entry in entries[:500]:
        request = entry.get("request") or {}
        response = entry.get("response") or {}
        url = str(request.get("url") or "")
        if not url or not target_is_in_scope(url, scopes)[0]:
            continue

        method = str(request.get("method") or "GET").upper()
        status = response.get("status")
        resource_type = str(entry.get("_resourceType") or entry.get("resourceType") or "")
        cookies_seen = len(request.get("cookies") or [])
        item = BrowserRequest(
            method,
            url,
            int(status) if isinstance(status, int) else None,
            resource_type,
            _headers(request.get("headers")),
            _headers(response.get("headers")),
            cookies_seen,
            "HAR",
        )
        requests.append(item)
        evidence.extend(
            [
                Evidence("browser_request", f"{method} {url}", url),
                Evidence("browser_response_status", str(status), url),
                Evidence("browser_resource_type", resource_type, url),
            ]
        )

    origins = sorted({f"{urlparse(item.url).scheme}://{urlparse(item.url).netloc}" for item in requests})
    paths = sorted({urlparse(item.url).path for item in requests})
    methods = sorted({item.method for item in requests})
    signals = []
    all_headers = {header for item in requests for header in item.request_headers}
    if "cookie" in all_headers or any(item.cookies_seen for item in requests):
        signals.append("cookie-backed-session")
    if "authorization" in all_headers:
        signals.append("authorization-header-session")
    if any(item.method in {"POST", "PUT", "PATCH", "DELETE"} for item in requests):
        signals.append("state-changing-browser-actions-observed")
    if any("graphql" in item.url.lower() for item in requests):
        signals.append("graphql-browser-traffic")
    if any(item.resource_type.lower() in {"xhr", "fetch"} for item in requests):
        signals.append("api-xhr-fetch-traffic")

    model = BrowserSessionModel(requests, origins, paths, methods, sorted(set(signals)))
    evidence.append(Evidence("browser_session_summary", json.dumps({
        "requests": len(requests),
        "origins": origins,
        "paths": paths[:100],
        "methods": methods,
        "stateful_signals": model.stateful_signals,
    }), "browser-trace"))
    return model, evidence


def load_har(path: str, scopes) -> tuple[BrowserSessionModel, list[Evidence]]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    return parse_har(payload, scopes)


def browser_model_json(model: BrowserSessionModel) -> dict:
    return {
        "requests": [asdict(item) for item in model.requests],
        "origins": model.origins,
        "paths": model.paths,
        "methods": model.methods,
        "stateful_signals": model.stateful_signals,
    }
