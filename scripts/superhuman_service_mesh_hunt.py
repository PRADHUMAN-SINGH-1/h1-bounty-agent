#!/usr/bin/env python3
import json
import urllib.error, urllib.request
from pathlib import Path

UA="H1-Bounty-Agent/0.4"
targets=[
 "https://gateway.superhuman.com/authorship/v1/",
 "https://gateway.superhuman.com/mise/api/v1",
 "https://gateway.superhuman.com/passport/api/v1/passport",
 "https://gateway.superhuman.com/snippets/v1/snippets",
 "https://gateway.superhuman.com/knowledge-hub/v1/institution",
 "https://gateway.superhuman.com/settings-registry/v1",
 "https://gateway.superhuman.com/institution/api/institution/admin",
 "https://gateway.superhuman.com/graphql",
 "https://id.superhuman.com/.well-known/openid-configuration",
 "https://id.superhuman.com/.well-known/openid-configuration/",
 "https://id.superhuman.com/api",
 "https://id.superhuman.com/api/v1",
 "https://id.superhuman.com/session",
 "https://id.superhuman.com/userinfo",
 "https://settings.superhuman.com/api",
 "https://settings.superhuman.com/api/v1",
 "https://settings.superhuman.com/settings",
 "https://settings.superhuman.com/organizations",
 "https://settings.superhuman.com/workspaces",
]
def get(u):
    req=urllib.request.Request(u,headers={"User-Agent":UA,"Accept":"application/json,text/plain,*/*"})
    try:
        with urllib.request.urlopen(req,timeout=12) as r:
            return r.status,dict(r.headers.items()),r.read(8000).decode("utf-8","replace")
    except urllib.error.HTTPError as e:
        return e.code,dict(e.headers.items()),e.read(8000).decode("utf-8","replace")
    except Exception as e:
        return 0,{},repr(e)

rows=[]
for u in targets:
    st,h,b=get(u)
    row={
      "url":u,"status":st,"content_type":h.get("Content-Type",""),
      "length":len(b),"location":h.get("Location",""),
      "acao":h.get("Access-Control-Allow-Origin",""),
      "acac":h.get("Access-Control-Allow-Credentials",""),
      "body_prefix":b[:800]
    }
    rows.append(row)
    print(json.dumps(row,ensure_ascii=False))

# High-signal anonymous data only. Generic 200/404 pages are not findings.
markers=("email","user_id","workspace","organization","document","access_token","refresh_token")
hits=[
 x for x in rows if 200<=x["status"]<300 and any(k in x["body_prefix"].lower() for k in markers)
 and x["length"]>100
 and "error" not in x["body_prefix"].lower()[:200]
]
Path("superhuman-service-mesh.json").write_text(json.dumps(rows,indent=2))
if hits:
    Path("superhuman-service-mesh-report.md").write_text(
      "# POTENTIAL ANONYMOUS SERVICE-MESH EXPOSURE\n\n"+
      "\n".join("- "+json.dumps(x,ensure_ascii=False) for x in hits)+
      "\n\nManual authorization/impact validation is required before submission.\n"
    )
    print("POTENTIAL ANONYMOUS SERVICE-MESH EXPOSURE")
else:
    Path("superhuman-service-mesh-report.md").write_text(
      "# NO VERIFIED ANONYMOUS SERVICE-MESH EXPOSURE\n\n"+
      "The tested known service endpoints did not return a high-signal anonymous data response.\n"
    )
    print("NO VERIFIED ANONYMOUS SERVICE-MESH EXPOSURE")
