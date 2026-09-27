#!/usr/bin/env python3
import json, ssl, urllib.request, urllib.error, hashlib
from pathlib import Path

DOC="1198436185"
URLS=[
    f"https://dox.grammarly.com/documents/{DOC}/download",
    f"https://dox.grammarly.com/documents/{DOC}",
    f"https://app.grammarly.com/ddocs/{DOC}",
    f"https://capi.grammarly.com/api/documents/{DOC}",
    f"https://capi.grammarly.com/api/v1/documents/{DOC}",
]
UA="H1-Bounty-Agent/ctf-download-1.2"
FLAG_RE=["$FLAG","h1_ctf@grammarly.com","1411519194"]

def req(url, method="GET"):
    r=urllib.request.Request(url, method=method, headers={"User-Agent":UA,"Accept":"*/*","Cache-Control":"no-cache"})
    try:
        with urllib.request.urlopen(r, timeout=20, context=ssl.create_default_context()) as x:
            body=x.read(300000).decode("utf-8","replace")
            return {"status":x.status,"allow":x.headers.get("Allow",""),"ctype":x.headers.get("Content-Type",""),"loc":x.headers.get("Location",""),"length":len(body),"body":body}
    except urllib.error.HTTPError as e:
        body=e.read(100000).decode("utf-8","replace")
        return {"status":e.code,"allow":e.headers.get("Allow",""),"ctype":e.headers.get("Content-Type",""),"loc":e.headers.get("Location",""),"length":len(body),"body":body}
    except Exception as e:
        return {"status":0,"error":repr(e),"body":""}

def main():
    rows=[]
    for u in URLS:
        methods = ["HEAD","OPTIONS","GET"] if u.endswith("/download") else ["GET","HEAD","OPTIONS"]
        for m in methods:
            x=req(u,m)
            body=x.get("body","")
            rows.append({"url":u,"method":m,**{k:v for k,v in x.items() if k!="body"},"flag_hits":[p for p in FLAG_RE if p in body],"body_sha256":hashlib.sha256(body.encode()).hexdigest()})
    findings=[r for r in rows if r["method"]=="GET" and r["flag_hits"]]
    out={"document":DOC,"rows":rows,"findings":findings}
    Path("ctf-download-results.json").write_text(json.dumps(out,indent=2),encoding="utf-8")
    if findings:
        Path("ctf-download-report.md").write_text("# VERIFIED CTF DOCUMENT FLAG EXPOSURE\n\n" + "\n".join("- URL: %s\n- Status: %s\n- Content-Type: %s\n- Flag marker(s): %s\n" % (r["url"],r["status"],r["ctype"],r["flag_hits"]) for r in findings),encoding="utf-8")
        print("VERIFIED CTF DOCUMENT FLAG EXPOSURE")
        for r in findings: print(json.dumps(r))
    else:
        Path("ctf-download-report.md").write_text("# NO VERIFIED CTF DOCUMENT FLAG EXPOSURE\n\nThe anonymous read-only checks returned no CTF flag marker.\n",encoding="utf-8")
        print("NO VERIFIED CTF DOCUMENT FLAG EXPOSURE")

if __name__=="__main__": main()