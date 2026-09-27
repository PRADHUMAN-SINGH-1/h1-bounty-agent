import json,re,subprocess,html
from pathlib import Path
from urllib.parse import urlencode

BASES=['https://developer.konghq.com/search','https://konghq.com/search']
PAYLOAD='KONG_XSS_CANARY_7f19b'
HTML_PAYLOAD='<img src=x onerror=KONG_XSS_CANARY_7f19b>'
PARAMS=['q','query','search','term']

def req(url):
    p=subprocess.run(['curl','-sS','--max-redirs','5','--connect-timeout','8','--max-time','15','-D','/tmp/h','-o','/tmp/b',url],text=True,capture_output=True)
    h=Path('/tmp/h').read_text(errors='replace') if Path('/tmp/h').exists() else ''
    b=Path('/tmp/b').read_text(errors='replace') if Path('/tmp/b').exists() else ''
    sts=re.findall(r'^HTTP/[^ ]+\s+(\d+)',h,re.M)
    status=int(sts[-1]) if sts else None
    ct=next((x.split(':',1)[1].strip() for x in h.splitlines() if x.lower().startswith('content-type:')),'')
    return status,ct,b,p.returncode

rows=[]
for base in BASES:
    for key in PARAMS:
        for value in [PAYLOAD,HTML_PAYLOAD]:
            url=base+'?'+urlencode({key:value})
            status,ct,body,code=req(url)
            raw=value in body
            encoded=(value.replace('<','&lt;').replace('>','&gt;') in body or html.escape(value) in body)
            context=[]
            idx=body.find(PAYLOAD)
            if idx>=0: context=[body[max(0,idx-180):idx+300]]
            row={'url':url,'status':status,'content_type':ct,'length':len(body),'raw_marker_reflected':raw,'encoded_marker_reflected':encoded,'context':context,'exit_code':code}
            rows.append(row)
            if raw: print(json.dumps(row))
Path('kong-search-xss-results.json').write_text(json.dumps(rows,indent=2))
hits=[x for x in rows if x['raw_marker_reflected'] and x['content_type'].lower().startswith('text/html') and x['status'] in (200,201,202,203,204)]
if hits:
    x=hits[0]
    Path('kong-search-xss-report.md').write_text(
      '# POTENTIAL REFLECTED XSS ON KONG PUBLIC SEARCH\n\n'
      '## Endpoint\n'+x['url'].split('?',1)[0]+'\n\n'
      '## Evidence\n- HTTP status: '+str(x['status'])+'\n- Content-Type: '+x['content_type']+'\n- Raw marker reflected: yes\n- Context: '+x['context'][0]+'\n\n'
      'Execution was not attempted; browser validation is required before submission.\n'
    )
else:
    Path('kong-search-xss-report.md').write_text('# NO VERIFIED REFLECTED XSS\n\nNo raw XSS marker was reflected into an HTML response on the tested public search pages.\n')
print(json.dumps({'tested':len(rows),'raw_reflections':len(hits)}))