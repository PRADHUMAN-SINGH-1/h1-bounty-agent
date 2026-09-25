#!/usr/bin/env python3
import json, urllib.error, urllib.parse, urllib.request
from pathlib import Path

CANARY = "https://h1-oauth-redirect-canary.invalid/callback"

def req(url, headers=None):
    r=urllib.request.Request(url, headers=headers or {"User-Agent":"H1-Bounty-Agent/0.4"})
    try:
        with urllib.request.urlopen(r, timeout=15) as x:
            return x.status, dict(x.headers.items()), x.read(10000).decode("utf-8","replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers.items()), e.read(10000).decode("utf-8","replace")
    except Exception as e:
        return 0, {}, repr(e)

def main():
    tests=[]
    # Current Superhuman Docs uses id.superhuman.com for unified login.
    # These are unauthenticated redirect-validation probes only: no credentials,
    # no real authorization code, no account mutation.
    base="https://id.superhuman.com"
    common = {
        "response_type":"code",
        "client_id":"superhumanDocs",
        "scope":"openid",
        "state":"h1-canary-state",
        "response_mode":"query",
    }
    for path in ["/signin", "/tokens/v4/api/oauth2/authorize", "/oauth2/authorize", "/v4/api/oauth2/authorize"]:
        for key in ["redirect_uri","redirect","return_to","next"]:
            q=dict(common)
            q[key]=CANARY
            url=base+path+"?"+urllib.parse.urlencode(q)
            status, headers, body=req(url)
            loc=headers.get("Location","") or headers.get("location","")
            row={
                "url":url, "status":status, "location":loc,
                "canary_in_location": CANARY in loc,
                "body_prefix":body[:600],
            }
            tests.append(row)
            print(json.dumps(row,ensure_ascii=False))

    # Check for permissive post-auth return parameters at the documented sign-in route,
    # again without performing an actual sign-in.
    findings=[x for x in tests if x["canary_in_location"]]
    Path("identity-oauth-probes.json").write_text(json.dumps(tests,indent=2))
    if findings:
        Path("identity-oauth-report.md").write_text(
            "# POTENTIAL OAUTH REDIRECT VALIDATION ISSUE\n\n"+
            "\n".join("- "+json.dumps(x,ensure_ascii=False) for x in findings)+
            "\n\nManual validation is required with a researcher-owned test account before submission.\n"
        )
        print("POTENTIAL OAUTH REDIRECT VALIDATION ISSUE")
    else:
        Path("identity-oauth-report.md").write_text(
            "# NO VERIFIED OAUTH REDIRECT ISSUE\n\n"
            "No tested identity endpoint returned the controlled external redirect target.\n"
        )
        print("NO VERIFIED OAUTH REDIRECT ISSUE")

if __name__=="__main__":
    main()
