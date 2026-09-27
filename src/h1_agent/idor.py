from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

import httpx

from .models import Evidence
from .scope import target_is_in_scope


_ID_RE = re.compile(
    r"(?<![A-Za-z0-9])(?:\d{2,20}|[0-9a-f]{8}-[0-9a-f-]{27,36}|[0-9a-f]{24})(?![A-Za-z0-9])",
    re.I,
)
_OWNER_RE = re.compile(
    r"""["'](?P<key>(?:owner|user|account|workspace|organization|tenant|project|team)[_-]?(?:id|uuid)?)["']\s*:\s*["']?(?P<value>[A-Za-z0-9._:-]{2,128})["']?""",
    re.I,
)
_ABS_URL_RE = re.compile(r'''https?://[^\s"'<>\\]+''', re.I)
_REL_URL_RE = re.compile(r"""["'](?P<url>/[^"'<>\s]{3,500})["']""")
_PRIVATE_PATH_HINTS = (
    "/api/",
    "/users/",
    "/accounts/",
    "/workspaces/",
    "/organizations/",
    "/tenants/",
    "/projects/",
    "/teams/",
    "/documents/",
    "/invoices/",
    "/orders/",
    "/messages/",
    "/profiles/",
    "/settings/",
)


@dataclass(frozen=True)
class ObjectAccessObservation:
    original_url: str
    candidate_url: str
    status_a: int
    status_b: int
    fingerprint_a: str
    fingerprint_b: str
    object_id: str
    ownership_binding: str
    suspicious: bool
    reason: str


def _fp(text: str) -> str:
    return hashlib.sha256(text[:250_000].encode("utf-8", errors="replace")).hexdigest()[:16]


def _ids_from_text(text: str) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    for match in _ID_RE.findall(text[:500_000]):
        if match not in seen:
            seen.add(match)
            found.append(match)
    return found[:20]


def _ownership_pairs(text: str) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for match in _OWNER_RE.finditer(text[:500_000]):
        pair = (match.group("key"), match.group("value"))
        if pair not in seen:
            seen.add(pair)
            found.append(pair)
    return found[:12]


def _candidate_urls(text: str, base_url: str) -> list[str]:
    results: list[str] = []
    seen: set[str] = set()
    candidates = list(_ABS_URL_RE.findall(text[:500_000])) + [
        urljoin(base_url, value) for value in _REL_URL_RE.findall(text[:500_000])
    ]
    for candidate in candidates:
        cleaned = candidate.rstrip(").,;")
        if cleaned in seen:
            continue
        seen.add(cleaned)
        if _ids_from_text(cleaned):
            results.append(cleaned)
    return results[:24]


def _private_object_hint(url: str) -> bool:
    path = (urlparse(url).path or "").lower()
    return any(part in path for part in _PRIVATE_PATH_HINTS)


def _same_binding(pairs: list[tuple[str, str]], body: str) -> str:
    for key, value in pairs:
        if value and re.search(rf"(?<![A-Za-z0-9]){re.escape(value)}(?![A-Za-z0-9])", body[:500_000]):
            return f"{key}={value}"
    return ""


class ObjectAuthorizationTester:
    """Read-only BOLA/IDOR tester using two explicitly authorized, distinct test accounts.

    The tester never mutates an object identifier. It first obtains an object using
    account A, then requests that exact same object URL with account B. A candidate
    is only marked suspicious when account A's response exposes an ownership binding
    and account B's response still exposes the same object identifier and ownership
    binding while returning HTTP 2xx.
    """

    def __init__(self, client: httpx.Client, header_a: str, header_b: str, max_urls: int = 8):
        self.client = client
        self.header_a = self._header(header_a)
        self.header_b = self._header(header_b)
        if self.header_a == self.header_b:
            raise ValueError("AUTHZ_HEADER_A and AUTHZ_HEADER_B must represent two distinct test-account sessions.")
        self.max_urls = max(1, max_urls)

    @staticmethod
    def _header(value: str):
        if ":" not in value:
            raise ValueError("Authorization test headers must use 'Name: value' format.")
        name, raw = value.split(":", 1)
        name, raw = name.strip(), raw.strip()
        if not name or not raw:
            raise ValueError("Authorization test headers must use 'Name: value' format.")
        return name, raw

    def run(self, urls: list[str], scopes) -> tuple[list[ObjectAccessObservation], list[Evidence]]:
        observations: list[ObjectAccessObservation] = []
        evidence: list[Evidence] = []

        for seed_url in urls:
            if len(observations) >= self.max_urls:
                break
            if not target_is_in_scope(seed_url, scopes)[0]:
                continue

            try:
                response_a = self.client.get(
                    seed_url,
                    headers={self.header_a[0]: self.header_a[1]},
                    follow_redirects=False,
                )
            except httpx.HTTPError:
                continue
            if not (200 <= response_a.status_code < 300):
                continue

            candidates: list[str] = []
            if _ids_from_text(seed_url):
                candidates.append(seed_url)
            candidates.extend(_candidate_urls(response_a.text, seed_url))

            seen_candidates: set[str] = set()
            for candidate_url in candidates:
                if len(observations) >= self.max_urls:
                    break
                if candidate_url in seen_candidates:
                    continue
                seen_candidates.add(candidate_url)
                if not target_is_in_scope(candidate_url, scopes)[0] or not _ids_from_text(candidate_url):
                    continue

                if candidate_url == seed_url:
                    object_response_a = response_a
                else:
                    try:
                        object_response_a = self.client.get(
                            candidate_url,
                            headers={self.header_a[0]: self.header_a[1]},
                            follow_redirects=False,
                        )
                    except httpx.HTTPError:
                        continue

                if not (200 <= object_response_a.status_code < 300):
                    continue

                object_ids = _ids_from_text(candidate_url)
                if not object_ids:
                    continue
                object_id = object_ids[0]
                ownership_pairs = _ownership_pairs(object_response_a.text)
                if not ownership_pairs:
                    continue

                try:
                    response_b = self.client.get(
                        candidate_url,
                        headers={self.header_b[0]: self.header_b[1]},
                        follow_redirects=False,
                    )
                except httpx.HTTPError:
                    continue

                binding = _same_binding(ownership_pairs, response_b.text)
                same_object = object_id in _ids_from_text(response_b.text)
                b_success = 200 <= response_b.status_code < 300
                suspicious = bool(
                    b_success
                    and same_object
                    and binding
                    and _private_object_hint(candidate_url)
                )
                if suspicious:
                    reason = (
                        "Account A can read an object bound to "
                        f"{binding}; account B can read the exact same object URL and response "
                        "contains the same object identifier plus the A-owned binding."
                    )
                elif b_success and same_object:
                    reason = (
                        "Account B can read the exact object URL, but no sufficiently strong "
                        "ownership binding was reproduced, so this is not treated as a verified BOLA signal."
                    )
                else:
                    reason = "Account B was denied or did not receive the same object representation."

                observation = ObjectAccessObservation(
                    original_url=seed_url,
                    candidate_url=candidate_url,
                    status_a=object_response_a.status_code,
                    status_b=response_b.status_code,
                    fingerprint_a=_fp(object_response_a.text),
                    fingerprint_b=_fp(response_b.text),
                    object_id=object_id,
                    ownership_binding=binding,
                    suspicious=suspicious,
                    reason=reason,
                )
                observations.append(observation)

                evidence.extend(
                    [
                        Evidence("idor_original_url", seed_url, seed_url),
                        Evidence("idor_candidate_url", candidate_url, candidate_url),
                        Evidence("idor_status_a", str(object_response_a.status_code), candidate_url),
                        Evidence("idor_status_b", str(response_b.status_code), candidate_url),
                        Evidence("idor_object_id", object_id, candidate_url),
                        Evidence("idor_owner_binding_a", ownership_pairs[0][0] + "=" + ownership_pairs[0][1], candidate_url),
                        Evidence("idor_owner_binding_b", binding or "not reproduced", candidate_url),
                        Evidence("idor_fingerprint_a", _fp(object_response_a.text), candidate_url),
                        Evidence("idor_fingerprint_b", _fp(response_b.text), candidate_url),
                        Evidence("idor_same_object_access", str(b_success and same_object).lower(), candidate_url),
                        Evidence("idor_ownership_binding", str(bool(binding)).lower(), candidate_url),
                        Evidence("idor_suspicious", str(suspicious).lower(), candidate_url),
                        Evidence("idor_observation", reason, candidate_url),
                    ]
                )
                break

        return observations, evidence
