from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from urllib.parse import urlparse

import httpx

from .models import Evidence
from .scope import target_is_in_scope


_ID_RE = re.compile(
    r"(?<![A-Za-z0-9])(?:\d{2,20}|[0-9a-f]{8}-[0-9a-f-]{27,36}|[0-9a-f]{24})(?![A-Za-z0-9])",
    re.I,
)


@dataclass(frozen=True)
class ObjectAccessObservation:
    original_url: str
    candidate_url: str
    status_a: int
    status_b: int
    fingerprint_a: str
    fingerprint_b: str
    suspicious: bool
    reason: str


def _fp(text: str) -> str:
    return hashlib.sha256(text[:250_000].encode(errors="replace")).hexdigest()[:16]


def _ids_from_body(text: str) -> list[str]:
    found = []
    seen = set()
    for match in _ID_RE.findall(text[:500_000]):
        if match not in seen:
            seen.add(match)
            found.append(match)
    return found[:12]


def _replace_id(url: str, old: str, new: str) -> str:
    return url.replace(old, new, 1)


class ObjectAuthorizationTester:
    """Read-only IDOR/BOLA candidate finder using two explicitly authorized accounts."""

    def __init__(self, client: httpx.Client, header_a: str, header_b: str, max_urls: int = 8):
        self.client = client
        self.header_a = self._header(header_a)
        self.header_b = self._header(header_b)
        self.max_urls = max(1, max_urls)

    @staticmethod
    def _header(value: str):
        if ":" not in value:
            raise ValueError("Authorization test headers must use 'Name: value' format.")
        name, raw = value.split(":", 1)
        return name.strip(), raw.strip()

    def run(self, urls: list[str], scopes) -> tuple[list[ObjectAccessObservation], list[Evidence]]:
        observations = []
        evidence = []
        for url in urls:
            if len(observations) >= self.max_urls:
                break
            if not target_is_in_scope(url, scopes)[0]:
                continue
            try:
                a = self.client.get(
                    url, headers={self.header_a[0]: self.header_a[1]}, follow_redirects=False
                )
            except httpx.HTTPError:
                continue
            if not (200 <= a.status_code < 300):
                continue

            ids = _ids_from_body(a.text)
            if not ids:
                ids = _ids_from_body(url)

            for object_id in ids[:4]:
                alternate = str(int(object_id) + 1) if object_id.isdigit() else object_id[::-1]
                candidate = _replace_id(url, object_id, alternate)
                if candidate == url or not target_is_in_scope(candidate, scopes)[0]:
                    continue
                try:
                    b = self.client.get(
                        candidate, headers={self.header_b[0]: self.header_b[1]}, follow_redirects=False
                    )
                except httpx.HTTPError:
                    continue

                suspicious = 200 <= b.status_code < 300 and (
                    "api" in urlparse(candidate).path.lower()
                    or "user" in urlparse(candidate).path.lower()
                    or "account" in urlparse(candidate).path.lower()
                    or "order" in urlparse(candidate).path.lower()
                    or "invoice" in urlparse(candidate).path.lower()
                )
                reason = (
                    "Object-like identifier changed and the second authorized account received a successful response; manual ownership validation required."
                    if suspicious
                    else "No strong unauthorized object-access signal."
                )
                obs = ObjectAccessObservation(
                    url,
                    candidate,
                    a.status_code,
                    b.status_code,
                    _fp(a.text),
                    _fp(b.text),
                    suspicious,
                    reason,
                )
                observations.append(obs)
                evidence.extend(
                    [
                        Evidence("idor_original_url", url, url),
                        Evidence("idor_candidate_url", candidate, candidate),
                        Evidence("idor_status_a", str(a.status_code), url),
                        Evidence("idor_status_b", str(b.status_code), candidate),
                        Evidence("idor_observation", reason, candidate),
                        Evidence("idor_suspicious", str(suspicious).lower(), candidate),
                    ]
                )
                break

        return observations, evidence
