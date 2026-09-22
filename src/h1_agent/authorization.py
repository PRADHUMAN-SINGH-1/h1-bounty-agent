from __future__ import annotations

import hashlib
from dataclasses import dataclass
from urllib.parse import urlparse

import httpx

from .models import Evidence


@dataclass(frozen=True)
class DifferentialResult:
    url: str
    status_a: int | None
    status_b: int | None
    body_fingerprint_a: str
    body_fingerprint_b: str
    content_type_a: str
    content_type_b: str
    suspicious: bool
    reason: str


def parse_header(value: str) -> tuple[str, str] | None:
    if not value or ":" not in value:
        return None
    name, header_value = value.split(":", 1)
    name = name.strip()
    header_value = header_value.strip()
    if not name or not header_value:
        return None
    return name, header_value


def _fingerprint(text: str) -> str:
    return hashlib.sha256(text[:250_000].encode("utf-8", errors="replace")).hexdigest()[:16]


class AuthorizationDifferentialTester:
    """Read-only differential checks using two explicitly supplied test accounts."""

    def __init__(
        self,
        client: httpx.Client,
        header_a: str,
        header_b: str,
        max_endpoints: int = 12,
    ):
        parsed_a = parse_header(header_a)
        parsed_b = parse_header(header_b)
        if not parsed_a or not parsed_b:
            raise ValueError(
                "AUTHZ_HEADER_A and AUTHZ_HEADER_B must each be a single HTTP header, e.g. "
                "'Authorization: Bearer …' or 'Cookie: session=…'."
            )
        self.client = client
        self.header_a = parsed_a
        self.header_b = parsed_b
        self.max_endpoints = max(1, max_endpoints)

    def compare(self, urls: list[str]) -> list[DifferentialResult]:
        results: list[DifferentialResult] = []
        seen: set[str] = set()

        for url in urls:
            if url in seen:
                continue
            seen.add(url)
            parsed = urlparse(url)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                continue
            try:
                response_a = self.client.get(
                    url,
                    headers={self.header_a[0]: self.header_a[1]},
                    follow_redirects=False,
                )
                response_b = self.client.get(
                    url,
                    headers={self.header_b[0]: self.header_b[1]},
                    follow_redirects=False,
                )
            except httpx.HTTPError:
                continue

            body_a = response_a.text[:250_000]
            body_b = response_b.text[:250_000]
            fp_a = _fingerprint(body_a)
            fp_b = _fingerprint(body_b)
            ct_a = response_a.headers.get("content-type", "")
            ct_b = response_b.headers.get("content-type", "")
            suspicious, reason = self._classify(
                response_a.status_code,
                response_b.status_code,
                body_a,
                body_b,
                ct_a,
                ct_b,
            )
            results.append(
                DifferentialResult(
                    url=url,
                    status_a=response_a.status_code,
                    status_b=response_b.status_code,
                    body_fingerprint_a=fp_a,
                    body_fingerprint_b=fp_b,
                    content_type_a=ct_a,
                    content_type_b=ct_b,
                    suspicious=suspicious,
                    reason=reason,
                )
            )
            if len(results) >= self.max_endpoints:
                break

        return results

    @staticmethod
    def _classify(
        status_a: int,
        status_b: int,
        body_a: str,
        body_b: str,
        content_type_a: str,
        content_type_b: str,
    ) -> tuple[bool, str]:
        # A 2xx vs 401/403 is expected authorization behavior, not a finding.
        if 200 <= status_a < 300 and status_b in {401, 403}:
            return False, "Account B is denied while A is allowed."
        if 401 <= status_a <= 403 and 200 <= status_b < 300:
            return True, "Account B is allowed while A is denied; verify account roles and ownership."
        if 200 <= status_a < 300 and 200 <= status_b < 300:
            # Equal status alone proves nothing. A large response similarity can be useful
            # context only when the researcher already knows the endpoint is object-sensitive.
            if body_a and body_b and body_a == body_b:
                return False, "Both accounts receive identical successful content."
            return False, "Both accounts receive successful responses with different content."
        if status_a != status_b:
            return False, "Accounts receive different HTTP status codes; manual authorization review required."
        return False, "No authorization differential observed."


def evidence_from_results(results: list[DifferentialResult]) -> list[Evidence]:
    evidence: list[Evidence] = []
    for result in results:
        evidence.extend(
            [
                Evidence("authz_url", result.url, result.url),
                Evidence("authz_status_a", str(result.status_a), result.url),
                Evidence("authz_status_b", str(result.status_b), result.url),
                Evidence("authz_fingerprint_a", result.body_fingerprint_a, result.url),
                Evidence("authz_fingerprint_b", result.body_fingerprint_b, result.url),
                Evidence("authz_content_type_a", result.content_type_a, result.url),
                Evidence("authz_content_type_b", result.content_type_b, result.url),
                Evidence("authz_observation", result.reason, result.url),
                Evidence("authz_suspicious", str(result.suspicious).lower(), result.url),
            ]
        )
    return evidence
