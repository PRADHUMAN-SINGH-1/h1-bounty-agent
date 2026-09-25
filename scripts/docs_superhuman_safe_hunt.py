#!/usr/bin/env python3
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

BASE = "https://docs.superhuman.com"
TIMEOUT = 15
CANARY = "https://h1-open-redirect-canary.invalid/"
ORIGIN = "https://h1-cors-canary.invalid"

def request(url, *, method="GET", headers=None, data=None):
    req = urllib.request.Request(url, method=method, headers=headers or {}, data=data)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            body = r.read(200000)
            return {
                "status": r.status,
                "headers": {k.lower(): v for k, v in r.headers.items()},
                "body": body.decode("utf-8", "replace"),
                "error": "",
            }
    except urllib.error.HTTPError as e:
        body = e.read(200000).decode("utf-8", "replace")
        return {
            "status": e.code,
            "headers": {k.lower(): v for k, v in e.headers.items()},
            "body": body,
            "error": "",
        }
    except Exception as e:
        return {"status": 0, "headers": {}, "body": "", "error": repr(e)}

def main():
    rows = []
    paths = [
        "/", "/account", "/apis/v1", "/apis/v1/whoami", "/apis/v1/docs",
        "/apis/admin/v1", "/apis/admin/v1/organizations", "/apis/mcp",
        "/apis/v1/docs/not-a-real-doc-id",
        "/apis/admin/v1/organizations/not-a-real-org-id",
    ]
    for path in paths:
        url = BASE + path
        r = request(url, headers={"User-Agent": "H1-Bounty-Agent/0.4"})
        row = {
            "url": url, "status": r["status"], "length": len(r["body"]),
            "location": r["headers"].get("location", ""),
            "content_type": r["headers"].get("content-type", ""),
            "acao": r["headers"].get("access-control-allow-origin", ""),
            "acac": r["headers"].get("access-control-allow-credentials", ""),
            "body_prefix": r["body"][:500],
            "error": r["error"],
        }
        rows.append(row)

    open_redirects = []
    for path in ["/", "/account", "/signin", "/login"]:
        for key in ["next", "redirect", "url", "returnTo", "return_url", "continue", "destination"]:
            q = urllib.parse.urlencode({key: CANARY})
            r = request(BASE + path + "?" + q, headers={"User-Agent": "H1-Bounty-Agent/0.4"})
            loc = r["headers"].get("location", "")
            if loc.startswith(CANARY):
                open_redirects.append({"url": BASE + path + "?" + q, "status": r["status"], "location": loc})

    cors = []
    for path in ["/apis/v1", "/apis/v1/whoami", "/apis/v1/docs", "/apis/admin/v1",
                 "/apis/admin/v1/organizations", "/apis/mcp", "/account"]:
        r = request(BASE + path, headers={"User-Agent": "H1-Bounty-Agent/0.4", "Origin": ORIGIN})
        acao = r["headers"].get("access-control-allow-origin", "")
        acac = r["headers"].get("access-control-allow-credentials", "")
        if (acao == ORIGIN or acao == "*") and acac.lower() == "true":
            cors.append({"url": BASE + path, "status": r["status"], "acao": acao, "acac": acac})

    init = json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "H1-Bounty-Agent", "version": "0.4"},
        },
    }).encode()
    m = request(
        BASE + "/apis/mcp",
        method="POST",
        headers={
            "User-Agent": "H1-Bounty-Agent/0.4",
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        },
        data=init,
    )
    mcp = {
        "status": m["status"],
        "session_id_present": bool(m["headers"].get("mcp-session-id")),
        "content_type": m["headers"].get("content-type", ""),
        "length": len(m["body"]),
        "body_prefix": m["body"][:1200],
        "error": m["error"],
    }

    findings = []
    findings.extend({"class": "open_redirect", **x} for x in open_redirects)
    findings.extend({"class": "credentialed_cors_reflection", **x} for x in cors)
    if mcp["status"] >= 200 and mcp["status"] < 300 and mcp["body"].strip():
        findings.append({"class": "anonymous_mcp_transport_response", **mcp})

    Path("docs-superhuman-results.json").write_text(json.dumps({
        "surface": rows, "open_redirects": open_redirects, "cors": cors, "mcp": mcp,
        "findings": findings,
    }, indent=2))
    if findings:
        Path("docs-superhuman-report.md").write_text(
            "# POTENTIAL FINDINGS\n\n" +
            "\n".join("- " + json.dumps(x, ensure_ascii=False) for x in findings) +
            "\n\nManual validation is required before any HackerOne submission.\n"
        )
        print("POTENTIAL FINDINGS")
        for x in findings:
            print(json.dumps(x, ensure_ascii=False))
    else:
        Path("docs-superhuman-report.md").write_text(
            "# NO VERIFIED FINDING FROM SAFE DOCS TESTS\n\n"
            "No external redirect, credentialed CORS reflection, or authenticated MCP bypass was observed.\n"
        )
        print("NO VERIFIED FINDING FROM SAFE DOCS TESTS")

if __name__ == "__main__":
    main()
