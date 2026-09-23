from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from urllib.parse import urlparse

from .models import Evidence
from .scope import target_is_in_scope


@dataclass(frozen=True)
class ToolRun:
    name: str
    status: str
    detail: str
    lines: list[str]


def _cmd(name: str) -> str | None:
    return shutil.which(name)


def _run(name: str, args: list[str], *, stdin: str = "", timeout: int = 900) -> ToolRun:
    executable = _cmd(name)
    if not executable:
        return ToolRun(name, "unavailable", f"{name} is not installed on this runner.", [])
    try:
        proc = subprocess.run(
            [executable, *args],
            input=stdin,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return ToolRun(name, "timeout", f"{name} timed out after {timeout}s.", [])
    output = (proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    status = "ok" if proc.returncode == 0 else "error"
    return ToolRun(name, status, f"exit={proc.returncode}; lines={len(lines)}", lines)


def _hosts_from_urls(urls: list[str]) -> list[str]:
    hosts: list[str] = []
    seen: set[str] = set()
    for value in urls:
        host = (urlparse(value).hostname or "").lower()
        if host and host not in seen:
            seen.add(host)
            hosts.append(host)
    return hosts


def _in_scope_lines(lines: list[str], scopes) -> list[str]:
    allowed: list[str] = []
    seen: set[str] = set()
    for line in lines:
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        candidate = value
        if not candidate.startswith(("http://", "https://")) and "." in candidate:
            candidate = "https://" + candidate
        ok, _asset, _reason = target_is_in_scope(candidate, scopes)
        if ok and value not in seen:
            seen.add(value)
            allowed.append(value)
    return allowed


def run_deep_toolchain(
    roots: list[str],
    scopes,
    *,
    max_roots: int = 10,
    max_targets: int = 50,
    httpx_timeout: int = 120,
    katana_timeout: int = 180,
    nuclei_timeout: int = 180,
    active: bool = False,
) -> tuple[list[Evidence], list[ToolRun]]:
    roots = _hosts_from_urls(roots)[:max_roots]
    evidence: list[Evidence] = []
    runs: list[ToolRun] = []
    if not roots:
        return evidence, runs

    discovered: list[str] = []
    for root in roots:
        result = _run(
            "subfinder",
            ["-d", root, "-silent", "-timeout", "30", "-max-time", "1"],
            timeout=min(90, nuclei_timeout),
        )
        runs.append(result)
        allowed = _in_scope_lines(result.lines, scopes)
        discovered.extend(allowed)
        evidence.append(Evidence("tool_subfinder_summary", f"{root}: {result.status}; {result.detail}", root))
        for item in allowed[:200]:
            evidence.append(Evidence("subdomain_discovered", item, root))

    targets = []
    for root in roots + discovered:
        candidate = root if root.startswith(("http://", "https://")) else f"https://{root}"
        ok, _asset, _reason = target_is_in_scope(candidate, scopes)
        if ok and candidate not in targets:
            targets.append(candidate)
    targets = targets[:max_targets]

    with tempfile.TemporaryDirectory(prefix="h1-toolchain-") as temp_dir:
        targets_file = os.path.join(temp_dir, "targets.txt")
        with open(targets_file, "w", encoding="utf-8") as handle:
            handle.write("\n".join(targets) + "\n")

        if targets:
            result = _run(
                "httpx",
                ["-l", targets_file, "-silent", "-json", "-title", "-tech-detect", "-status-code",
                 "-follow-redirects", "-rate-limit", "2", "-threads", "5"],
                timeout=httpx_timeout,
            )
            runs.append(result)
            for line in result.lines[:1000]:
                try:
                    item = json.loads(line)
                    url = str(item.get("url") or item.get("input") or "")
                except json.JSONDecodeError:
                    continue
                if not url:
                    continue
                ok, _asset, _reason = target_is_in_scope(url, scopes)
                if ok:
                    evidence.append(Evidence("httpx_probe", json.dumps(item, ensure_ascii=False)[:5000], url))

            result = _run(
                "katana",
                ["-list", targets_file, "-silent", "-depth", "2", "-jc",
                 "-known-files", "robotstxt,sitemapxml", "-rate-limit", "2",
                 "-concurrency", "2", "-timeout", "8"],
                timeout=katana_timeout,
            )
            runs.append(result)
            crawled = _in_scope_lines(result.lines, scopes)
            for url in crawled[:1000]:
                evidence.append(Evidence("katana_endpoint", url, url))

            for tool_name, args in (("gau", ["--subs"]), ("waybackurls", [])):
                if not _cmd(tool_name):
                    continue
                for root in roots:
                    result = _run(tool_name, args, stdin=root + "\n", timeout=min(120, katana_timeout))
                    runs.append(result)
                    for url in _in_scope_lines(result.lines, scopes)[:500]:
                        evidence.append(Evidence("historical_url", url, root))

            nuclei_args = [
                "-l", targets_file,
                "-silent",
                "-jsonl",
                "-rate-limit", "2",
                "-concurrency", "2",
                "-bulk-size", "2",
                "-exclude-tags", "dos,intrusive",
                "-severity", "info,low,medium,high,critical",
                "-no-interactsh",
            ]
            result = _run("nuclei", nuclei_args, timeout=nuclei_timeout)
            runs.append(result)
            for line in result.lines[:1000]:
                try:
                    item = json.loads(line)
                    matched = str(item.get("matched-at") or item.get("host") or item.get("url") or "nuclei")
                    detail = json.dumps(item, ensure_ascii=False)[:7000]
                except json.JSONDecodeError:
                    matched = "nuclei"
                    detail = line[:7000]
                evidence.append(Evidence("nuclei_match", detail, matched))

    if active and roots:
        evidence.append(Evidence(
            "active_toolchain_gate",
            "Active fuzzing/enumeration tools remain disabled in this build; explicit authorized active testing must be separately enabled.",
            "h1-bounty-agent",
        ))
    return evidence, runs
