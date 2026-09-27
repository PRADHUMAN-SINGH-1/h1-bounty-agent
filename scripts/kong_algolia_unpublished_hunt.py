#!/usr/bin/env python3
import json
import re
import urllib.parse
import urllib.request
from pathlib import Path

SITE = "https://developer.konghq.com/search/"
INDEX = "kongdeveloper"
QUERIES = [
    "Jaeger protocol support in the Kong Zipkin plugin",
    "AI MCP OAuth2 Policy",
    "multi-layer AI guardrails",
    "How do I manage AI Gateway with kongctl",
    "Unpublished Vertex AI is being retired",
]

def get(url, headers=None):
    req = urllib.request.Request(url, headers=headers or {"User-Agent":"H1-Bounty-Agent/0.9"})
    with urllib.request.urlopen(req, timeout=20) as r:
        return r.status, {k.lower():v for k,v in r.headers.items()}, r.read(500000).decode("utf-8","replace")

def post(url, body, headers):
    req = urllib.request.Request(
        url, method="POST",
        headers={**headers, "Content-Type":"application/json","User-Agent":"H1-Bounty-Agent/0.9"},
        data=json.dumps(body).encode()
    )
    with urllib.request.urlopen(req, timeout=20) as r:
        return r.status, {k.lower():v for k,v in r.headers.items()}, r.read(500000).decode("utf-8","replace")

def main():
    status, headers, html = get(SITE)
    # Find production-injected Algolia credentials in HTML or linked JS.
    app_id = None
    api_key = None
    assets = re.findall(r'<script[^>]+src="([^"]+)"', html)
    candidates = [SITE]
    for src in assets[:40]:
        candidates.append(urllib.parse.urljoin(SITE, src))

    texts = [(SITE, html)]
    for url in candidates[1:]:
        try:
            s, h, t = get(url)
            if "algolia" in t.lower():
                texts.append((url,t))
        except Exception:
            pass

    app_patterns = [
        r'VITE_ALGOLIA_APPLICATION_ID["\'\s:=]+([A-Z0-9]{5,})',
        r'algoliaApplicationId["\'\s:=]+([A-Z0-9]{5,})',
        r'algolia.*?application.*?([A-Z0-9]{5,})',
    ]
    key_patterns = [
        r'VITE_ALGOLIA_API_KEY["\'\s:=]+([A-Za-z0-9_-]{20,})',
        r'algoliaApiKey["\'\s:=]+([A-Za-z0-9_-]{20,})',
    ]
    for _, text in texts:
        if not app_id:
            for p in app_patterns:
                m = re.search(p, text, re.I)
                if m: app_id = m.group(1); break
        if not api_key:
            for p in key_patterns:
                m = re.search(p, text, re.I)
                if m: api_key = m.group(1); break
        if app_id and api_key: break

    result = {
        "site_status": status,
        "app_id_found": bool(app_id),
        "api_key_found": bool(api_key),
        "tested_queries": QUERIES,
        "hits": [],
    }

    if app_id and api_key:
        endpoint = f"https://{app_id}-dsn.algolia.net/1/indexes/{urllib.parse.quote(INDEX, safe='')}/query"
        hdr = {
            "X-Algolia-Application-Id": app_id,
            "X-Algolia-API-Key": api_key,
        }
        for q in QUERIES:
            try:
                s, h, body = post(endpoint, {"query": q, "hitsPerPage": 10}, hdr)
                data = json.loads(body)
                hits = data.get("hits", [])
                # Keep only compact, non-sensitive fields.
                compact = []
                for hit in hits:
                    compact.append({
                        "url": hit.get("url") or hit.get("objectID"),
                        "title": hit.get("title"),
                        "content_type": hit.get("content_type"),
                        "published": hit.get("published"),
                        "snippet": (hit.get("content") or hit.get("_snippetResult",{})) if isinstance(hit.get("content"), str) else "",
                    })
                result["hits"].append({"query":q,"status":s,"count":len(hits),"records":compact})
            except Exception as exc:
                result["hits"].append({"query":q,"error":repr(exc)})
    else:
        result["error"] = "Could not extract production Algolia credentials from accessible HTML/JS."

    findings = []
    for item in result["hits"]:
        for rec in item.get("records", []):
            title = (rec.get("title") or "").lower()
            snippet = (rec.get("snippet") or "").lower()
            unpublished_terms = ["jaeger protocol support", "ai mcp oauth2", "multi-layer ai guardrails", "manage ai gateway with kongctl", "unpublished: vertex ai"]
            if any(t in (title + " " + snippet) for t in unpublished_terms):
                findings.append({"query":item["query"],"record":rec})

    result["findings"] = findings
    Path("kong-algolia-unpublished-results.json").write_text(json.dumps(result, indent=2), encoding="utf-8")

    if findings:
        Path("kong-algolia-unpublished-report.md").write_text(
            "# POTENTIAL UNPUBLISHED CONTENT EXPOSURE VIA ALGOLIA\n\n" +
            "\n".join(f"- Query: {x['query']}\n  Record: {json.dumps(x['record'], ensure_ascii=False)}" for x in findings) +
            "\n",
            encoding="utf-8",
        )
        print("POTENTIAL UNPUBLISHED CONTENT EXPOSURE")
        for x in findings:
            print(json.dumps(x, ensure_ascii=False))
    else:
        Path("kong-algolia-unpublished-report.md").write_text(
            "# NO VERIFIED UNPUBLISHED CONTENT EXPOSURE VIA ALGOLIA\n\n"
            "No tested unpublished-page marker was returned from the public Algolia search index.\n",
            encoding="utf-8",
        )
        print("NO VERIFIED UNPUBLISHED CONTENT EXPOSURE VIA ALGOLIA")

if __name__ == "__main__":
    main()
