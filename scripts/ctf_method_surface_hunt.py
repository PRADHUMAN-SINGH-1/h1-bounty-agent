#!/usr/bin/env python3
import json, ssl, urllib.request, urllib.error
from pathlib import Path

DOC="1198436185"
URLS=[
 f"https://app.grammarly.com/ddocs/{DOC}",
 f"https://dox.grammarly.com/documents/{DOC}",
 f"https://dox.grammarly.com/document/{DOC}",
 f"https://dox.grammarly.com/documents/{DOC}/proofread",
 f"https://dox.grammarly.com/document/{DOC}/proofread",
 f"https://dox.grammarly.com/documents/{DOC}/content",
 f"https://dox.grammarly.com/documents/{DOC}/data",
 f"https://dox.grammarly.com/documents/{DOC}/download",
 f"https://dox.grammarly.com/documents/{DOC}/export",
 f"https://dox.grammarly.com/documents/{DOC}/raw",
 f"https://capi.grammarly.com/api/documents/{DOC}",
 f"https://capi.grammarly.com/api/v1/documents/{DOC}",
 f"https://capi.grammarly.com/api/cheetah/v1/documents/{DOC}",
]
QUERY_CANDIDATES=["view","format","download","export","raw","content","include","mode","type"]
UA="H1-Bounty-Agent/ctf-surface-1.1"

def req(url,method):
    r=urllib.request.Request(url,method=method,headers={"User-Agent":UA,"Accept":"*/*"})
    try:
        with urllib.request.urlopen(r,timeout=15,context=ssl.create_default_context()) as x:
            body=x.read(120000).decode("utf-8","replace")
            return {"status":x.status,"allow":x.headers.get("Allow",""),"ctype":x.headers.get("Content-Type",""),
                    "loc":x.headers.get("Location",""),"length":len(body),
                    "flag_like":["$FLAG" in body,"h1_ctf@" in body,"1198436185" in body],
                    "prefix":body[:1000]}
    except urllib.error.HTTPError as e:
        body=e.read(50000).decode("utf-8","replace")
        return {"status":e.code,"allow":e.headers.get("Allow",""),"ctype":e.headers.get("Content-Type",""),
                "loc":e.headers.get("Location",""),"length":len(body),
                "flag_like":["$FLAG" in body,"h1_ctf@" in body,"1198436185" in body],
                "prefix":body[:1000]}
    except Exception as e:
        return {"status":0,"error":repr(e)}

def main():
    rows=[]
    for u in URLS:
        for m in ["HEAD","OPTIONS"]:
            rows.append({"url":u,"method":m,**req(u,m)})
    # Read-only query variants against the known CTF document URL.
    for u in URLS[:5]:
        sep="&" if "?" in u else "?"
        for key in QUERY_CANDIDATES:
            q=u+sep+key+"=1"
            rows.append({"url":q,"method":"GET",**req(q,"GET")})

    findings=[]
    for r in rows:
        if any(r.get("flag_like") or []):
            findings.append(r)
        if r.get("status") in {200,206} and r.get("ctype","").lower().startswith(("application/json","text/plain","text/html")):
            if r.get("method")=="GET" and r.get("length",0) > 0 and any(r.get("flag_like") or []):
                findings.append(r)

    out={"document":DOC,"rows":rows,"findings":findings}
    Path("ctf-method-surface-results.json").write_text(json.dumps(out,indent=2),encoding="utf-8")
    if findings:
        Path("ctf-method-surface-report.md").write_text(
            "# POTENTIAL CTF DOCUMENT EXPOSURE\n\n"+
            "\n".join("- "+json.dumps(x,ensure_ascii=False) for x in findings)+"\n",encoding="utf-8")
        print("POTENTIAL CTF DOCUMENT EXPOSURE")
    else:
        Path("ctf-method-surface-report.md").write_text(
            "# NO VERIFIED CTF DOCUMENT EXPOSURE\n\n"
            "HEAD/OPTIONS and read-only GET query/path variants returned no challenge flag.\n",encoding="utf-8")
        print("NO VERIFIED CTF DOCUMENT EXPOSURE")

if __name__=="__main__": main()
