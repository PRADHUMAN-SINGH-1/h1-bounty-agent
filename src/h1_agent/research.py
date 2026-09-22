from __future__ import annotations

import time
from dataclasses import dataclass
from urllib.parse import urljoin

import httpx

from .config import Settings
from .models import Evidence, ScopeAsset
from .scope import require_in_scope
from .vulnerability_checks import (
    api_spec_probe,
    cookie_probe,
    cors_probe,
    discover_page,
    interesting_query_links,
    mixed_content_probe,
    open_redirect_probe,
    reflection_probe,
    sourcemap_probe,
)


@dataclass(frozen=True)
class CheckResult:
    name: str
    status: str
    detail: str
    evidence: list[Evidence]


class LowImpactResearch:
    """Scope-gated HTTP evidence collection with optional non-destructive probes."""

    def __init__(self, settings: Settings, scopes: list[ScopeAsset]):
        self.settings = settings
        self.scopes = scopes
        self.last_request = 0.0
        self.client = httpx.Client(
            follow_redirects=True,
            timeout=12,
            headers={"User-Agent": settings.user_agent},
        )

    def close(self) -> None:
        self.client.close()

    def _wait(self) -> None:
        interval = 1 / max(self.settings.requests_per_second, 0.1)
        remaining = interval - (time.monotonic() - self.last_request)
        if remaining > 0:
            time.sleep(remaining)
        self.last_request = time.monotonic()

    def _get(self, url: str, **kwargs) -> httpx.Response:
        self._wait()
        return self.client.get(url, **kwargs)

    def _options(self, url: str) -> httpx.Response:
        self._wait()
        return self.client.options(url)

    def _head(self, url: str) -> httpx.Response:
        self._wait()
        return self.client.head(url, follow_redirects=False)

    def run(self, target: str, *, active: bool = False) -> list[CheckResult]:
        asset = require_in_scope(target, self.scopes)
        if active and not self.settings.allow_active_tests:
            raise PermissionError(
                "Active testing is disabled. Set ALLOW_ACTIVE_TESTS=true only after reviewing program policy."
            )
        if asset.instruction:
            instruction = asset.instruction.strip().replace("\n", " ")
            raise PermissionError(
                "This asset has program-specific instructions. Review them manually before active testing: "
                + instruction[:600]
            )

        base = target if target.endswith("/") else target + "/"
        results, home_response = self._get_home(base)

        for path in ("robots.txt", ".well-known/security.txt", "sitemap.xml"):
            results.append(self._get_metadata(base, path))

        results.append(self._options_probe(base))

        if active and home_response is not None:
            results.extend(self._active_assessment(base, home_response))

        return results

    def _get_home(self, url: str) -> tuple[list[CheckResult], httpx.Response | None]:
        try:
            r = self._get(url)
            headers = {k.lower(): v for k, v in r.headers.items()}
            evidence = [
                Evidence("status", str(r.status_code), url),
                Evidence("final_url", str(r.url), url),
                Evidence("content_type", headers.get("content-type", ""), url),
                Evidence("server", headers.get("server", ""), url),
            ]
            for name in (
                "content-security-policy",
                "strict-transport-security",
                "x-content-type-options",
                "x-frame-options",
                "referrer-policy",
                "permissions-policy",
            ):
                evidence.append(Evidence(name, headers.get(name, "missing"), url))
            cookie_status, cookie_evidence = cookie_probe(r, url)
            evidence.extend(cookie_evidence)
            result = CheckResult("homepage", "ok", f"HTTP {r.status_code}; cookie={cookie_status}", evidence)
            return [result], r
        except httpx.HTTPError as exc:
            return [CheckResult("homepage", "error", str(exc), [Evidence("error", str(exc), url)])], None

    def _get_metadata(self, base: str, path: str) -> CheckResult:
        url = urljoin(base, path)
        try:
            r = self._get(url)
            return CheckResult(
                path,
                "found" if r.status_code < 400 else "absent",
                f"HTTP {r.status_code}",
                [
                    Evidence("status", str(r.status_code), url),
                    Evidence("content_type", r.headers.get("content-type", ""), url),
                    Evidence("location", r.headers.get("location", ""), url),
                ],
            )
        except httpx.HTTPError as exc:
            return CheckResult(path, "error", str(exc), [Evidence("error", str(exc), url)])

    def _options_probe(self, url: str) -> CheckResult:
        try:
            r = self._options(url)
            return CheckResult(
                "options_metadata",
                "ok",
                f"HTTP {r.status_code}",
                [
                    Evidence("allow", r.headers.get("allow", ""), url),
                    Evidence("access-control-allow-origin", r.headers.get("access-control-allow-origin", ""), url),
                    Evidence("access-control-allow-methods", r.headers.get("access-control-allow-methods", ""), url),
                ],
            )
        except httpx.HTTPError as exc:
            return CheckResult("options_metadata", "error", str(exc), [Evidence("error", str(exc), url)])

    def _active_assessment(self, base: str, home_response: httpx.Response) -> list[CheckResult]:
        checks: list[CheckResult] = []
        html = home_response.text[:2_000_000]
        links, scripts, _forms = discover_page(html, base)
        query_links = interesting_query_links(links, base)

        status, evidence = cors_probe(self.client, base, self._get)
        checks.append(CheckResult("cors_probe", status, status.replace("_", " "), evidence))

        if query_links:
            for url in query_links[:4]:
                status, evidence = reflection_probe(self.client, url, self._get)
                if status != "skipped":
                    checks.append(CheckResult("reflection_probe", status, f"Query reflection check for {url}", evidence))

                status, evidence = open_redirect_probe(self.client, url, self._get)
                if status != "skipped":
                    checks.append(CheckResult("open_redirect_probe", status, f"Redirect parameter check for {url}", evidence))

        status, evidence = sourcemap_probe(self.client, scripts, self._get)
        checks.append(CheckResult("sourcemap_probe", status, status.replace("_", " "), evidence))

        status, evidence = api_spec_probe(base, self._get)
        checks.append(CheckResult("api_spec_probe", status, status.replace("_", " "), evidence))

        status, evidence = mixed_content_probe(base, html)
        checks.append(CheckResult("mixed_content_probe", status, status.replace("_", " "), evidence))

        return checks


def flatten(results: list[CheckResult]) -> list[Evidence]:
    evidence: list[Evidence] = []
    for result in results:
        evidence.extend(result.evidence)
    return evidence
