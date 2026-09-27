import json,re,subprocess
from pathlib import Path

BASE='https://mcp.konghq.com'
paths=['/','/sse','/mcp','/health','/healthz','/.well-known','/.well-known/mcp.json','/robots.txt']
def req(path):
    url=BASE+path
    p=subprocess.run(['curl','-sS','--max-redirs','0','--connect-timeout','8','--max-time','15','-H','Accept: text/event-stream, application/json, */*','-D','/tmp/h','-o','/tmp/b',url],text=True,capture_output=True)
    h=Path('/tmp/h').read_text(errors='replace') if Path('/tmp/h').exists() else ''
    b=Path('/tmp/b').read_text(errors='replace') if Path('/tmp/b').exists() else ''
    sts=re.findall(r'^HTTP/[^ ]+\s+(\d+)',h,re.M)
    status=int(sts[-1]) if sts else None
    ct=next((x.split(':',1)[1].strip() for x in h.splitlines() if x.lower().startswith('content-type:')),'')
    allow=next((x.split(':',1)[1].strip() for x in h.splitlines() if x.lower().startswith('allow:')),'')
    return {'url':url,'status':status,'content_type':ct,'allow':allow,'length':len(b),'body_prefix':b[:600]}
rows=[req(x) for x in paths]
Path('kong-mcp-public-results.json').write_text(json.dumps(rows,indent=2))
interesting=[x for x in rows if x['status'] and 200 <= x['status'] < 300 and x['url'].endswith(('/sse','/mcp')) and x['length']>0]
if interesting:
    x=interesting[0]
    Path('kong-mcp-public-report.md').write_text(
        '# Potential unauthenticated Kong MCP surface exposure\n\n'
        '## Endpoint\n'+x['url']+'\n\n'
        '## Evidence\n'
        '- HTTP status: '+str(x['status'])+'\n'
        '- Content-Type: '+x['content_type']+'\n'
        '- Response length: '+str(x['length'])+' bytes\n'
        '- Response prefix: '+x['body_prefix']+'\n\n'
        'This is a candidate only; control-plane access must be demonstrated using a researcher-owned Konnect account before submission.\n'
    )
else:
    Path('kong-mcp-public-report.md').write_text('# NO VERIFIED UNAUTHENTICATED MCP ACCESS\n\nNo public MCP endpoint returned a high-signal unauthenticated response.\n')
print(json.dumps({'tested':len(rows),'interesting':len(interesting)}))