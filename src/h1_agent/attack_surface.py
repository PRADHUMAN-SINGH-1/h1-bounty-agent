from __future__ import annotations

import json
import re
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

from .models import Evidence


@dataclass(frozen=True)
class SurfaceEndpoint:
    url: str
    source: str
    method_hint: str = "GET"
    kind: str = "link"


def _same_origin(candidate: str, base: str) -> bool:
    a = urlparse(candidate)
    b = urlparse(base)
    if a.scheme not in {"http", "https"} or b.scheme not in {"http", "https"}:
        return False
    if a.scheme != b.scheme or not a.hostname or not b.hostname:
        return False

    def port(parsed):
        if parsed.port:
            return parsed.port
        return 443 if parsed.scheme == "https" else 80

    return a.hostname.lower() == b.hostname.lower() and port(a) == port(b)


def _add(results, seen, raw: str, base: str, source: str, method: str = "GET", kind: str = "link"):
    raw = raw.strip().strip("\"'")
    if not raw or raw.startswith(("javascript:", "mailto:", "tel:", "data:", "#")):
        return
    absolute = urljoin(base, raw)
    if not _same_origin(absolute, base):
        return
    parsed = urlparse(absolute)
    if not parsed.path or parsed.path == "/":
        return
    key = absolute.split("#", 1)[0]
    if key in seen:
        return
    seen.add(key)
    results.append(SurfaceEndpoint(key, source, method, kind))


def discover_from_html(html: str, base: str) -> list[SurfaceEndpoint]:
    results: list[SurfaceEndpoint] = []
    seen: set[str] = set()

    for match in re.finditer(r"""(?:href|action)=["']([^"']+)["']""", html[:2_000_000], flags=re.I):
        _add(results, seen, match.group(1), base, "html", kind="html")

    patterns = (
        r"""(?:fetch|axios\.(?:get|post|put|patch|delete)|XMLHttpRequest[^;]{0,120}?open)\s*\([^\n]{0,160}?["']([^"']+)["']""",
        r"""["']((?:/|https?://)[^"'\\s<>]{1,240})["']""",
    )
    for pattern in patterns:
        for match in re.finditer(pattern, html[:2_000_000], flags=re.I):
            _add(results, seen, match.group(1), base, "inline-js", kind="javascript")

    return results[:100]


def discover_from_javascript(text: str, script_url: str, base: str) -> list[SurfaceEndpoint]:
    results: list[SurfaceEndpoint] = []
    seen: set[str] = set()

    patterns = (
        r"""(?:fetch|axios\.(?:get|post|put|patch|delete)|XMLHttpRequest[^;]{0,120}?open)\s*\([^\n]{0,180}?["']([^"']+)["']""",
        r"""["']((?:/|https?://)(?:api|graphql|rest|v[0-9]+)?[^"'\\s<>]{1,240})["']""",
    )
    for pattern in patterns:
        for match in re.finditer(pattern, text[:1_500_000], flags=re.I):
            _add(results, seen, match.group(1), base, script_url, kind="javascript")
    return results[:100]


def discover_from_openapi(document: dict, base: str) -> list[SurfaceEndpoint]:
    results: list[SurfaceEndpoint] = []
    seen: set[str] = set()
    for path, operation_map in (document.get("paths") or {}).items():
        if not isinstance(path, str) or not isinstance(operation_map, dict):
            continue
        for method, operation in operation_map.items():
            if method.lower() not in {"get", "head", "options"} or not isinstance(operation, dict):
                continue
            _add(results, seen, path, base, "openapi", method.upper(), "openapi")
    return results[:150]


def parse_openapi(text: str) -> dict | None:
    try:
        payload = json.loads(text)
    except (TypeError, ValueError):
        return None
    if not isinstance(payload, dict):
        return None
    if "openapi" in payload or "swagger" in payload:
        return payload
    return None


def surface_evidence(endpoints: list[SurfaceEndpoint]) -> list[Evidence]:
    return [
        Evidence(
            "attack_surface_endpoint",
            f"{endpoint.method_hint} {endpoint.url} [{endpoint.kind}]",
            endpoint.source,
        )
        for endpoint in endpoints[:150]
    ]
