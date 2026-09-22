from __future__ import annotations

import time
from dataclasses import dataclass
from urllib.parse import urljoin

import httpx

from .config import Settings
from .models import Evidence, ScopeAsset
from .scope import require_in_scope


@dataclass(frozen=True)
class CheckResult:
    name: str
    status: str
    detail: str
    evidence: list[Evidence]


class LowImpactResearch:
    """Scope-gated, deliberately low-impact HTTP evidence collection."""

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

    def _get(self, url: str) -> httpx.Response:
        self._wait()
        return self.client.get(url)

    def _options(self, url: str) -> httpx.Response:
        self._wait()
        return self.client.options(url)

    def run(self, target: str) -> list[CheckResult]:
        asset = require_in_scope(target, self.scopes)
        if not self.settings.allow_active_tests:
            raise PermissionError("Active testing is disabled. Set ALLOW_ACTIVE_TESTS=true after reviewing program policy.")
        if asset.instruction:
            print_instruction = asset.instruction.strip().replace("\n", " ")
            raise PermissionError(
                "This asset has program-specific instructions. Review them manually before active testing: "
                + print_instruction[:600]
            )

        base = target if target.endswith("/") else target + "/"
        results = [self._get_home(base)]
        results.extend(self._get_metadata(base, p) for p in ("robots.txt", ".well-known/security.txt", "sitemap.xml"))
        results.append(self._options_probe(base))
        return results

    def _get_home(self, url: str) -> CheckResult:
        try:
            r = self._get(url)
            headers = {k.lower(): v for k, v in r.headers.items()}
            evidence = [
                Evidence("status", str(r.status_code), url),
                Evidence("final_url", str(r.url), url),
                Evidence("content_type", headers.get("content-type", ""), url),
                Evidence("server", headers.get("server", ""), url),
            ]
            for name in ("content-security-policy", "strict-transport-security", "x-content-type-options", "x-frame-options", "referrer-policy", "permissions-policy"):
                evidence.append(Evidence(name, headers.get(name, "missing"), url))
            return CheckResult("homepage", "ok", f"HTTP {r.status_code}", evidence)
        except httpx.HTTPError as exc:
            return CheckResult("homepage", "error", str(exc), [Evidence("error", str(exc), url)])

    def _get_metadata(self, base: str, path: str) -> CheckResult:
        url = urljoin(base, path)
        try:
            r = self._get(url)
            return CheckResult(path, "found" if r.status_code < 400 else "absent", f"HTTP {r.status_code}", [
                Evidence("status", str(r.status_code), url),
                Evidence("content_type", r.headers.get("content-type", ""), url),
                Evidence("location", r.headers.get("location", ""), url),
            ])
        except httpx.HTTPError as exc:
            return CheckResult(path, "error", str(exc), [Evidence("error", str(exc), url)])

    def _options_probe(self, url: str) -> CheckResult:
        try:
            r = self._options(url)
            return CheckResult("options_metadata", "ok", f"HTTP {r.status_code}", [
                Evidence("allow", r.headers.get("allow", ""), url),
                Evidence("access-control-allow-origin", r.headers.get("access-control-allow-origin", ""), url),
                Evidence("access-control-allow-methods", r.headers.get("access-control-allow-methods", ""), url),
            ])
        except httpx.HTTPError as exc:
            return CheckResult("options_metadata", "error", str(exc), [Evidence("error", str(exc), url)])


def flatten(results: list[CheckResult]) -> list[Evidence]:
    evidence: list[Evidence] = []
    for result in results:
        evidence.extend(result.evidence)
    return evidence
