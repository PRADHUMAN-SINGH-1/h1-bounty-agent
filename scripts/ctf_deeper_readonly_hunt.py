import json
import re
import subprocess
from pathlib import Path
from urllib.parse import urljoin, urlparse

DOC = '1198436185'
HOSTS = {'www.grammarly.com','app.grammarly.com','capi.grammarly.com','dox.grammarly.com','gateway.grammarly.com','data.grammarly.com'}
SEED = 'https://www.grammarly.com/'
HEADERS = {'User-Agent':'H1-Bounty-Agent/0.8','Accept':'*/*'}

def curl(url, method='GET', timeout=15, extra=None):
    args=['curl','-sS','--max-redirs','5','--connect-timeout','8','--max-time',str(timeout)]
    if method == 'HEAD': args += ['-I']
    elif method == 'OPTIONS': args += ['-X','OPTIONS']
    args += ['-D','/tmp/h1h','-o','/tmp/h1b']
    for k,v in {**HEADERS, **(extra or {})}.items(): args += ['-H',f'{k}: {v}']
    args += [url]
    p=subprocess.run(args,text=True,capture_output=True)
    h=Path('/tmp/h1h').read_text(errors='replace') if Path('/tmp/h1h').exists() else ''
    b=Path('/tmp/h1b').read_text(errors='replace') if Path('/tmp/h1b').exists() else ''
    statuses=re.findall(r'^HTTP/[^ ]+\s+(\d+)',h,re.M)
    status=statuses[-1] if statuses else ''
    ct=next((x.split(':',1)[1].strip() for x in h.splitlines() if x.lower().startswith('content-type:')),'')
    locs=[x.split(':',1)[1].strip() for x in h.splitlines() if x.lower().startswith('location:')]
    return {'url':url,'method':method,'status':status,'content_type':ct,'location':locs[-1] if locs else '','body':b,'exit_code':p.returncode}

def candidates_from(text, base):
    out=set()
    patterns=[
        r'''["'](https?://[^"'\\s]{1,500})''',
        r'''["']((?:/api|/documents|/document|/ddocs|/v1|/v2|/graphql)[^"'\\s]{1,400})''',
        r'''["']([^"'\\s]{0,180}(?:documents|document|ddocs|graphql|dox)[^"'\\s]{0,220})["']''',
    ]
    for pat in patterns:
        for m in re.findall(pat,text,re.I):
            u=m.strip('\\")]}>,.')
            u=u if u.startswith('http') else urljoin(base,u)
            p=urlparse(u)
            if p.hostname and p.hostname.lower() in HOSTS: out.add(u)
    return sorted(out)

seed=curl(SEED)
html=seed['body']
scripts=[]
for raw in re.findall(r'''<script[^>]+src=["']([^"']+)["']''',html,re.I):
    u=urljoin(SEED,raw)
    if (urlparse(u).hostname or '').lower() == 'www.grammarly.com': scripts.append(u)
scripts=list(dict.fromkeys(scripts))[:80]
bundle_hits=[]
all_candidates=set()
for u in scripts:
    r=curl(u,timeout=20)
    body=r['body']
    if body and re.search(r'1198436185|ddocs|documents|documentId|document_id|capi\\.grammarly|dox\\.grammarly|graphql',body,re.I):
        markers=sorted(set(re.findall(r'1198436185|ddocs|documents|documentId|document_id|capi\\.grammarly|dox\\.grammarly|graphql',body,re.I)))[:30]
        bundle_hits.append({'url':u,'length':len(body),'markers':markers})
        all_candidates.update(candidates_from(body,u))

base_candidates=[
    f'https://app.grammarly.com/ddocs/{DOC}',
    f'https://www.grammarly.com/ddocs/{DOC}',
    f'https://dox.grammarly.com/documents/{DOC}',
    f'https://capi.grammarly.com/api/documents/{DOC}',
    f'https://capi.grammarly.com/api/v1/documents/{DOC}',
    f'https://capi.grammarly.com/api/v2/documents/{DOC}',
    f'https://capi.grammarly.com/api/cheetah/v1/documents/{DOC}',
    f'https://dox.grammarly.com/api/documents/{DOC}',
    f'https://dox.grammarly.com/api/v1/documents/{DOC}',
    f'https://dox.grammarly.com/api/v2/documents/{DOC}',
    f'https://dox.grammarly.com/documents/{DOC}/content',
    f'https://dox.grammarly.com/documents/{DOC}/data',
    f'https://dox.grammarly.com/documents/{DOC}/download',
    f'https://dox.grammarly.com/documents/{DOC}/export',
]
targets=set(base_candidates)
for c in all_candidates:
    if DOC in c or any(k in c.lower() for k in ('/documents','/document','/ddocs','/graphql')): targets.add(c)
targets=sorted(targets)[:180]
results=[]
for u in targets:
    if (urlparse(u).hostname or '').lower() not in HOSTS: continue
    for method in ('GET','HEAD','OPTIONS'):
        r=curl(u,method=method,timeout=15)
        body=r['body']
        flags=sorted(set(re.findall(r'(?i)\$FLAG\s*[:=]\s*[^<\s]{4,250}|FLAG\{[^}]{4,250}\}|H1\{[A-Za-z0-9_-]{4,250}\}',body)))
        results.append({'url':u,'method':method,'status':r['status'],'content_type':r['content_type'],'location':r['location'],'length':len(body),'doc_id_present':DOC in body,'flag_hits':flags[:10],'exit_code':r['exit_code']})
        if flags: break

payload={'seed_status':seed['status'],'seed_length':len(html),'script_count':len(scripts),'bundle_hits':bundle_hits[:40],'candidate_count':len(all_candidates),'results':results}
Path('ctf-deeper-results.json').write_text(json.dumps(payload,indent=2))
flagged=[x for x in results if x['flag_hits']]
if flagged:
    x=flagged[0]
    report=('''# VERIFIED CTF FLAG EXPOSURE\n\n## Affected target\n%s\n\n## Method\n%s\n\n## Reproduction\n1. Send the recorded request without authentication.\n2. Observe HTTP %s.\n3. Inspect the response for the CTF flag.\n\n## Evidence\n- Status: %s\n- Content-Type: %s\n- Response length: %s bytes\n- Flag: %s\n''' % (x['url'],x['method'],x['status'],x['status'],x['content_type'],x['length'],x['flag_hits'][0]))
else:
    report='# NO VERIFIED CTF FLAG EXPOSURE\n\nCurrent public client bundles and bounded GET/HEAD/OPTIONS document/API routes were tested. No challenge flag was returned.\n'
Path('ctf-deeper-report.md').write_text(report)
print(json.dumps({'seed_status':seed['status'],'script_count':len(scripts),'bundle_hits':len(bundle_hits),'candidate_count':len(all_candidates),'flagged':bool(flagged)}))