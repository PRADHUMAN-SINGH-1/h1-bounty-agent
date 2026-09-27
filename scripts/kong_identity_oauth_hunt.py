#!/usr/bin/env python3
import json, urllib.parse, urllib.request
from pathlib import Path

BASES = [
    "https://us.identity.konghq.com",
    "https://us.identity.konghq.com/auth",
]
PATHS = [
    "/.well-known/openid-configuration",
    "/.well-known/jwks",
    "/oauth2/authorize",
    "/authorize",
    "/oauth/authorize",
    "/auth/.well-known/openid-configuration",
    "/auth/.well-known/jwks",
    "/auth/oauth2/authorize",
    "/auth/authorize",
]
CANARY = "https://h1-kong-open-redirect.invalid/cb"

def req(url):
    r = urllib.request.Request(url, headers={"User-Agent":"H1-Bounty-Agent/1.0 Kong Identity auth research"})
    try:
        with urllib.request.urlopen(r, timeout=15) as x:
            return {"status":x.status,"location":x.headers.get("Location",""),"ctype":x.headers.get("Content-Type",""),"body":x.read(200000).decode("utf-8","replace")[:2000]}
    except urllib.error.HTTPError as e:
        return {"status":e.code,"location":e.headers.get("Location",""),"ctype":e.headers.get("Content-Type",""),"body":e.read(200000).decode("utf-8","replace")[:2000]}
    except Exception as e:
        return {"status":0,"location":"","ctype":"","body":"","error":repr(e)}

def main():
    surface=[]
    for b in BASES:
        for p in PATHS:
            if b.endswith("/auth") and p.startswith("/auth/"):
                continue
            u=b+p
            x=req(u)
            surface.append({"url":u,**x})

    redirect_tests=[]
    for base in [b for b in BASES if b.endswith("/auth")]:
        for p in ["/oauth2/authorize","/authorize","/oauth/authorize"]:
            for key in ["redirect_uri","redirect","return_to","next"]:
                q=urllib.parse.urlencode({key:CANARY,"client_id":"invalid","response_type":"code"})
                u=base+p+"?"+q
                x=req(u)
                redirect_tests.append({"url":u,"key":key,**x})

    findings=[]
    for x in redirect_tests:
        loc=x.get("location","")
        if loc.startswith(CANARY):
            findings.append(x)

    out={"surface":surface,"redirect_tests":redirect_tests,"findings":findings}
    Path("kong-identity-results.json").write_text(json.dumps(out,indent=2),encoding="utf-8")
    if findings:
        Path("kong-identity-report.md").write_text(
            "# VERIFIED POTENTIAL OAUTH OPEN REDIRECT\n\n"+
            "\n".join("- "+json.dumps(x,ensure_ascii=False) for x in findings)+"\n",encoding="utf-8")
        print("VERIFIED POTENTIAL OAUTH OPEN REDIRECT")
        for x in findings: print(json.dumps(x,ensure_ascii=False))
    else:
        Path("kong-identity-report.md").write_text(
            "# NO VERIFIED OAUTH REDIRECT FINDING\n\nNo endpoint redirected to the external canary during anonymous invalid-client tests.\n",
            encoding="utf-8")
        print("NO VERIFIED OAUTH REDIRECT FINDING")

if __name__ == "__main__": main()
