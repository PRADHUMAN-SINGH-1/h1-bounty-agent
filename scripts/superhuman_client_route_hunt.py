#!/usr/bin/env python3
import json,re,urllib.parse,urllib.request
from pathlib import Path

UA="H1-Bounty-Agent/0.4"
bases=[
 "https://id.superhuman.com/signin",
 "https://settings.superhuman.com/",
 "https://gateway.superhuman.com/",
 "https://superhuman.com/",
]
scope_suffix=(".grammarly.com",".grammarly.io",".superhuman.com",".coda.io",".codacontent.io",".codahosted.io")

def get(u,limit=120000):
    try:
        req=urllib.request.Request(u,headers={"User-Agent":UA})
        with urllib.request.urlopen(req,timeout=15) as r:
            return r.read(limit).decode("utf-8","replace"),dict(r.headers.items()),r.status
    except Exception as e:
        return "",{},0

pages={}
scripts=set()
for base in bases:
    b,h,s=get(base)
    pages[base]={"status":s,"content_type":h.get("Content-Type",""),"length":len(b)}
    for m in re.finditer(r'<script[^>]+src=[\"\']([^\"\']+)',b,re.I):
        scripts.add(urllib.parse.urljoin(base,m.group(1)))

routes=set()
for su in list(scripts)[:25]:
    b,h,s=get(su,180000)
    # Capture same-scope absolute URLs.
    for m in re.finditer(r'https?://[A-Za-z0-9._:-]+(?:/[A-Za-z0-9_./?=&%:+@-]*)?',b):
        u=m.group(0).rstrip('\\\"\'<>),;')
        host=urllib.parse.urlparse(u).hostname or ""
        if host.endswith(scope_suffix):
            routes.add(u)
    # Capture API-looking relative paths.
    for m in re.finditer(r'(?<![A-Za-z0-9])/(?:api|apis|v[0-9]+|oauth|tokens|graphql|trpc|auth|session|admin|settings|workspace|workspaces|docs)(?:/[A-Za-z0-9_.$~:@%+\-]+){0,6}',b,re.I):
        p=m.group(0)
        if len(p)<220:
            routes.add(p)

roots=[
 "https://id.superhuman.com","https://settings.superhuman.com",
 "https://gateway.superhuman.com","https://superhuman.com"
]
api_urls=set()
for x in routes:
    if x.startswith("http"): api_urls.add(x)
    else:
        for r in roots:
            api_urls.add(urllib.parse.urljoin(r,x))

# Keep requests bounded and only API/auth-looking routes.
api_urls={u for u in api_urls if any(k in urllib.parse.urlparse(u).path.lower() for k in ("/api","/apis","/oauth","/token","/graphql","/auth","/session","/admin","/settings"))}
api_urls=sorted(api_urls)[:160]

probes=[]
for u in api_urls:
    b,h,s=get(u,16000)
    probes.append({
      "url":u,"status":s,"content_type":h.get("Content-Type",""),
      "length":len(b),"location":h.get("Location",""),
      "acao":h.get("Access-Control-Allow-Origin",""),
      "acac":h.get("Access-Control-Allow-Credentials",""),
      "body_prefix":b[:800]
    })

Path("superhuman-client-routes.json").write_text(json.dumps({
 "pages":pages,"script_count":len(scripts),"scripts":sorted(scripts)[:25],
 "routes":sorted(routes),"probes":probes
},indent=2))

high=[]
for x in probes:
    if x["status"] in (200,206) and x["length"]>0:
        body=x["body_prefix"].lower()
        if any(k in body for k in ("email","user_id","userid","workspace","document","token","secret","organization")):
            high.append(x)

if high:
    Path("superhuman-client-route-report.md").write_text(
      "# POTENTIAL UNAUTHENTICATED DATA-BEARING ROUTES\n\n"+
      "\n".join("- "+json.dumps(x,ensure_ascii=False) for x in high)+
      "\n\nManual validation is required; no authentication material was used.\n"
    )
    print("POTENTIAL UNAUTHENTICATED DATA-BEARING ROUTES")
    for x in high: print(json.dumps(x,ensure_ascii=False))
else:
    Path("superhuman-client-route-report.md").write_text(
      "# NO VERIFIED ANONYMOUS DATA-BEARING ROUTE\n\n"+
      "Client-discovered API/auth routes did not return an anonymous 2xx response containing a high-signal data field pattern.\n"
    )
    print("NO VERIFIED ANONYMOUS DATA-BEARING ROUTE")

if not probes:
    print("No API-like client routes discovered.")
