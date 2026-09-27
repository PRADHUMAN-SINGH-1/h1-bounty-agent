import json,re,subprocess
from pathlib import Path

TARGET='app.grammarly.com/ddocs/1198436185'
api='https://web.archive.org/cdx/search/cdx?url='+TARGET+'&output=json&filter=statuscode:200&fl=timestamp,original,statuscode,digest&collapse=digest'

def run(args):
    return subprocess.run(args,text=True,capture_output=True,timeout=30)

p=run(['curl','-sS','--connect-timeout','10','--max-time','25',api])
rows=[]
try: rows=json.loads(p.stdout)
except Exception: rows=[]
snapshots=[]
for row in rows[1:20] if isinstance(rows,list) and rows else []:
    ts=row[0]
    snap='https://web.archive.org/web/'+ts+'id_/https://'+TARGET
    q=run(['curl','-sS','--connect-timeout','10','--max-time','30','-L','--max-redirs','5',snap])
    body=q.stdout
    flags=sorted(set(re.findall(r'(?i)\$FLAG\s*[:=]\s*[^<\s]{4,250}|FLAG\{[^}]{4,250}\}|H1\{[A-Za-z0-9_-]{4,250}\}',body)))
    snapshots.append({'timestamp':ts,'snapshot_url':snap,'length':len(body),'exit_code':q.returncode,'flag_hits':flags[:10],'doc_id_present':TARGET.split('/')[-1] in body,'marker_hits':sorted(set(re.findall(r'(?i)1198436185|h1_ctf|documentId|document_id|ddocs',body)))[:20]})
Path('ctf-wayback-results.json').write_text(json.dumps({'cdx_status':p.returncode,'snapshot_count':len(snapshots),'snapshots':snapshots},indent=2))
flagged=[x for x in snapshots if x['flag_hits']]
if flagged:
    x=flagged[0]
    Path('ctf-wayback-report.md').write_text(
        '# HISTORICAL CTF FLAG LEAD\n\n'
        'Archived snapshot: '+x['snapshot_url']+'\n\n'
        'The historical copy contains a flag-shaped marker. This is not sufficient by itself for a bounty report; current live verification is required.\n\n'
        'Flag marker observed: '+x['flag_hits'][0]+'\n'
    )
else:
    Path('ctf-wayback-report.md').write_text('# NO HISTORICAL FLAG FOUND\n\nNo flag-shaped marker was found in the archived snapshots retrieved for the exact CTF URL.\n')
print(json.dumps({'cdx_exit':p.returncode,'snapshot_count':len(snapshots),'flagged_snapshots':len(flagged)}))