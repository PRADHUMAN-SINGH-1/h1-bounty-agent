import json,re,subprocess
from pathlib import Path
from urllib.parse import urljoin,urlparse

BASE='https://developer.konghq.com/'
paths=['robots.txt','sitemap.xml','.well-known/security.txt','.git/HEAD','.env','.env.production','admin','preview','api','api/health','api/search','_next/data','netlify/functions','__data','404','api-specs','openapi.json','swagger.json']
def req(url):
    p=subprocess.run(['curl','-sS','--path-as-is','--max-redirs','0','--connect-timeout','8','--max-time','12','-D','/tmp/h','-o','/tmp/b',url],text=True,capture_output=True)
    h=Path('/tmp/h').read_text(errors='replace') if Path('/tmp/h').exists() else ''
    b=Path('/tmp/b').read_text(errors='replace') if Path('/tmp/b').exists() else ''
    sts=re.findall(r'^HTTP/[^ ]+\s+(\d+)',h,re.M)
    status=int(sts[-1]) if sts else None
    ct=next((x.split(':',1)[1].strip() for x in h.splitlines() if x.lower().startswith('content-type:')),'')
    return {'url':url,'status':status,'content_type':ct,'length':len(b),'body':b[:500000]}
rows=[req(urljoin(BASE,p)) for p in paths]

seed=req(BASE)
links=[]
for raw in re.findall(r'''(?:href|src)=['"]([^'"]+)['"]''',seed['body'],re.I):
    u=urljoin(BASE,raw)
    if (urlparse(u).hostname or '').lower()=='developer.konghq.com': links.append(u)
links=list(dict.fromkeys(links))[:120]
for u in links:
    if any(x in u.lower() for x in ('preview','draft','admin','api','graphql','openapi','swagger','search')):
        rows.append(req(u))

secret=re.compile(r'(?i)(AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{30,}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|gh[pousr]_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{20,}|sk_(?:live|test)_[A-Za-z0-9]{20,})')
unpublished=re.compile(r'(?i)(draft|unpublished|preview|staging|internal|private|secret|cms[_-]?token|payload[_-]?cms|content[_-]?api|branch[_-]?deploy)')
findings=[]
for x in rows:
    body=x.pop('body')
    if x['status'] in (200,206) and body:
        secrets=sorted(set(m.group(0)[:12]+'…REDACTED' for m in secret.finditer(body)))
        markers=sorted(set(m.group(0).lower() for m in unpublished.finditer(body)))[:20]
        if secrets or (markers and x['url'].split('/',3)[-1] not in ('','robots.txt','sitemap.xml')):
            findings.append({**x,'secret_patterns':secrets,'unpublished_markers':markers,'body_prefix':body[:700]})
Path('kong-developer-unpublished-results.json').write_text(json.dumps({'tested_paths':len(rows),'links_examined':len(links),'findings':findings},indent=2))
if findings:
    x=findings[0]
    Path('kong-developer-unpublished-report.md').write_text(
        '# Potential Kong public-content exposure\n\n'
        '## Endpoint\n'+x['url']+'\n\n'
        '## Evidence\n- HTTP status: '+str(x['status'])+'\n- Content-Type: '+x['content_type']+'\n- Response length: '+str(x['length'])+' bytes\n- Secret-pattern classes: '+', '.join(x['secret_patterns'])+'\n- Unpublished markers: '+', '.join(x['unpublished_markers'])+'\n- Response prefix: '+x['body_prefix']+'\n'
    )
else:
    Path('kong-developer-unpublished-report.md').write_text('# NO VERIFIED PUBLIC-CONTENT EXPOSURE\n\nNo tested public endpoint exposed credential-like material or clearly unpublished internal content.\n')
print(json.dumps({'tested_paths':len(rows),'links_examined':len(links),'findings':len(findings)}))