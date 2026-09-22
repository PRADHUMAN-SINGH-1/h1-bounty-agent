from __future__ import annotations

import io
import json
import re
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

import httpx

from .cloud import analyze_cloud_text
from .mobile import analyze_mobile_package
from .models import Evidence, ScopeAsset


_MAX_TEXT = 750_000
_MAX_FILE_BYTES = 12 * 1024 * 1024
_MAX_FILES = 250


@dataclass(frozen=True)
class AssetAnalysis:
    status: str
    detail: str
    evidence: list[Evidence]


def _headers(settings) -> dict[str, str]:
    return {"User-Agent": settings.user_agent}


def _http_client(settings) -> httpx.Client:
    return httpx.Client(
        follow_redirects=False,
        timeout=20,
        headers=_headers(settings),
    )


def _bounded_text(text: str) -> str:
    return text[:_MAX_TEXT]


def _source_findings(text: str, source: str) -> list[Evidence]:
    evidence: list[Evidence] = []
    checks = {
        "secret_like_assignment": r"(?i)(api[_-]?key|secret|token|password|private[_-]?key)\s*[:=]\s*['\"][^'\"]{8,}",
        "jwt_like_value": r"\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b",
        "cloud_key_pattern": r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b",
        "internal_url": r"https?://(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+)(?::\d+)?",
        "debug_flag": r"(?i)\b(?:debug|development_mode|verbose_logging)\b\s*[:=]\s*(?:true|1|['\"]true['\"])",
        "cors_wildcard": r"(?i)access-control-allow-origin[^\\n]{0,120}\*",
    }
    for name, pattern in checks.items():
        matches = re.findall(pattern, text)
        if matches:
            evidence.append(
                Evidence(
                    "source_code_signal",
                    f"{name}: {len(matches)} match(es)",
                    source,
                )
            )

    endpoint_count = len(
        re.findall(r"(?i)(?:https?://|/api/|/v[0-9]+/|graphql|websocket)", text)
    )
    if endpoint_count:
        evidence.append(
            Evidence("source_code_endpoint_signals", str(endpoint_count), source)
        )
    return evidence


def _analyze_text_source(identifier: str, text: str) -> AssetAnalysis:
    bounded = _bounded_text(text)
    evidence = [
        Evidence("source_asset_url", identifier, identifier),
        Evidence("source_bytes_analyzed", str(len(bounded.encode("utf-8", errors="ignore"))), identifier),
    ]
    evidence.extend(_source_findings(bounded, identifier))
    status = "review" if len(evidence) > 2 else "observed"
    return AssetAnalysis(
        status,
        f"Analyzed scoped source artifact text; {len(evidence)} evidence items",
        evidence,
    )


def _repo_parts(identifier: str) -> tuple[str, str] | None:
    parsed = urlparse(identifier)
    if parsed.hostname not in {"github.com", "www.github.com"}:
        return None
    parts = [p for p in parsed.path.split("/") if p]
    if len(parts) < 2:
        return None
    return parts[0], parts[1]


def _analyze_github_repo(identifier: str, settings) -> AssetAnalysis:
    parts = _repo_parts(identifier)
    if not parts:
        return AssetAnalysis("skipped", "Not a supported GitHub repository URL.", [])
    owner, repo = parts
    api_url = f"https://api.github.com/repos/{owner}/{repo}/git/trees"
    client = _http_client(settings)
    evidence: list[Evidence] = []
    try:
        repo_response = client.get(f"https://api.github.com/repos/{owner}/{repo}")
        if repo_response.status_code != 200:
            return AssetAnalysis("skipped", f"GitHub repository metadata unavailable (HTTP {repo_response.status_code}).", [])
        default_branch = repo_response.json().get("default_branch") or "main"
        tree_response = client.get(
            f"https://api.github.com/repos/{owner}/{repo}/git/trees/{default_branch}",
            params={"recursive": "1"},
        )
        if tree_response.status_code != 200:
            return AssetAnalysis("skipped", f"GitHub source tree unavailable (HTTP {tree_response.status_code}).", [])

        tree = tree_response.json().get("tree", [])
        text_paths = [
            str(item.get("path"))
            for item in tree
            if item.get("type") == "blob"
            and item.get("size", 0) <= _MAX_FILE_BYTES
            and str(item.get("path", "")).lower().endswith(
                (".py", ".js", ".ts", ".tsx", ".jsx", ".java", ".kt", ".go", ".rb", ".php", ".json", ".yaml", ".yml", ".xml", ".env")
            )
        ][: _MAX_FILES]

        evidence.append(Evidence("source_repo", identifier, identifier))
        evidence.append(Evidence("source_file_count_analyzed", str(len(text_paths)), identifier))

        analyzed = 0
        for path in text_paths:
            raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/{default_branch}/{path}"
            response = client.get(raw_url)
            if response.status_code != 200:
                continue
            text = response.text[:_MAX_TEXT]
            findings = _source_findings(text, raw_url)
            if findings:
                analyzed += len(findings)
                evidence.extend(findings)

        status = "review" if analyzed else "observed"
        return AssetAnalysis(
            status,
            f"Analyzed {len(text_paths)} scoped source files; {analyzed} security-relevant source signals",
            evidence,
        )
    finally:
        client.close()


def _download_to_temp(url: str, settings) -> Path:
    client = _http_client(settings)
    try:
        response = client.get(url)
        response.raise_for_status()
        content = response.content
        if len(content) > _MAX_FILE_BYTES:
            raise ValueError(f"Artifact exceeds {_MAX_FILE_BYTES} bytes.")
        suffix = Path(urlparse(url).path).suffix or ".bin"
        handle = tempfile.NamedTemporaryFile(prefix="h1-artifact-", suffix=suffix, delete=False)
        handle.write(content)
        handle.flush()
        handle.close()
        return Path(handle.name)
    finally:
        client.close()


def analyze_asset(asset: ScopeAsset, settings) -> AssetAnalysis:
    kind = asset.asset_type.strip().upper()
    identifier = asset.asset_identifier.strip()
    if not identifier:
        return AssetAnalysis("skipped", "Empty scope identifier.", [])

    if kind in {"SOURCE_CODE", "SOURCE", "CODE"}:
        repo = _repo_parts(identifier)
        if repo:
            return _analyze_github_repo(identifier, settings)
        if identifier.startswith(("http://", "https://")):
            client = _http_client(settings)
            try:
                response = client.get(identifier)
                if response.status_code != 200:
                    return AssetAnalysis("skipped", f"Source artifact returned HTTP {response.status_code}.", [])
                content_type = response.headers.get("content-type", "")
                if "text" not in content_type and "json" not in content_type and "javascript" not in content_type:
                    return AssetAnalysis("skipped", "Source URL is not a text/code artifact.", [])
                return _analyze_text_source(identifier, response.text)
            finally:
                client.close()
        return AssetAnalysis("manual", "Source-code scope exists but no public artifact URL was supplied.", [
            Evidence("source_scope_manual_artifact_required", identifier, identifier)
        ])

    if kind in {"MOBILE_APP", "MOBILE", "APK", "IPA", "ANDROID_APP", "IOS_APP"}:
        if not identifier.startswith(("http://", "https://")):
            return AssetAnalysis("manual", "Mobile asset is in scope but requires an authorized APK/IPA artifact URL.", [
                Evidence("mobile_scope_manual_artifact_required", identifier, identifier)
            ])
        path = None
        try:
            path = _download_to_temp(identifier, settings)
            result, evidence = analyze_mobile_package(str(path))
            evidence.insert(0, Evidence("mobile_scope_asset", identifier, identifier))
            status = "review" if result.get("security_flags") or result.get("url_references") else "observed"
            return AssetAnalysis(status, f"Static mobile analysis completed: {result.get('files', 0)} package entries.", evidence)
        finally:
            if path is not None:
                try:
                    path.unlink(missing_ok=True)
                except OSError:
                    pass

    if kind in {"CLOUD", "CLOUD_ASSET", "IAM", "CLOUD_RESOURCE"}:
        if identifier.startswith(("http://", "https://")):
            client = _http_client(settings)
            try:
                response = client.get(identifier)
                if response.status_code != 200:
                    return AssetAnalysis("skipped", f"Cloud policy/resource returned HTTP {response.status_code}.", [])
                text = response.text[:_MAX_TEXT]
            finally:
                client.close()
        else:
            text = identifier
        result, evidence = analyze_cloud_text(text, identifier)
        result_evidence = [Evidence("cloud_scope_asset", identifier, identifier), *evidence]
        status = "review" if any(result.get(key) for key in ("aws_arns", "azure_storage_urls", "gcp_storage_hosts", "policy_observations")) else "observed"
        return AssetAnalysis(status, "Cloud/IAM footprint analysis completed.", result_evidence)

    if identifier.startswith(("http://", "https://")):
        return AssetAnalysis("web", "Route to HTTP research engine.", [
            Evidence("web_scope_asset", identifier, identifier)
        ])

    return AssetAnalysis("manual", "Scope asset requires a specialized artifact or authorized application context.", [
        Evidence("unsupported_scope_asset", f"{kind}: {identifier}", identifier)
    ])
