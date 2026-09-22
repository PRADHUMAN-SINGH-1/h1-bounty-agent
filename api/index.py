from __future__ import annotations

import json

from fastapi import Depends, FastAPI
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from h1_agent.config import Settings
from h1_agent.llm import LLMClient
from h1_agent.store import Store
from h1_agent.web_auth import action_token, require_basic

app = FastAPI(title="H1 Bounty Agent", version="0.4.0")
basic = HTTPBasic(auto_error=False)


def _auth(credentials: HTTPBasicCredentials | None = Depends(basic)) -> None:
    settings = Settings()
    require_basic(credentials, settings.dashboard_user, settings.dashboard_password)


@app.get("/", response_class=HTMLResponse, dependencies=[Depends(_auth)])
def dashboard() -> str:
    settings = Settings()
    token = action_token(settings.dashboard_secret)
    submit_enabled = settings.enable_submission

    page = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>H1 Bounty Agent</title>
<style>
body{margin:0;background:#070b12;color:#edf3fb;font-family:Inter,system-ui,sans-serif}
main{max-width:1100px;margin:0 auto;padding:32px 20px 60px}
h1{margin:0}.muted{color:#8fa3bf}.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin:22px 0}
.card{background:#111a29;border:1px solid #25354d;border-radius:16px;padding:18px}
.metric{font-size:28px;font-weight:750}.actions{display:flex;gap:10px;flex-wrap:wrap}
button{background:#182940;color:#fff;border:1px solid #304764;border-radius:10px;padding:10px 14px;cursor:pointer}
.primary{background:#71e0c0;color:#07110d;border:0}.danger{background:#ff7c89;color:#24080c;border:0}
.finding{margin-top:14px}.title{font-size:18px;font-weight:700}.meta{color:#8fa3bf;font-size:13px;margin-top:5px}
pre{white-space:pre-wrap;background:#080f1a;border:1px solid #25354d;border-radius:10px;padding:12px;overflow:auto}
.badge{display:inline-block;padding:4px 8px;border-radius:999px;background:#17243a;border:1px solid #304764;font-size:12px}
@media(max-width:800px){.grid{grid-template-columns:1fr}}
</style>
</head>
<body>
<main>
<div style="display:flex;justify-content:space-between;gap:20px;align-items:flex-start">
<div><h1>H1 Bounty Agent</h1><p class="muted">Authorized research → evidence → human validation → HackerOne</p></div>
<div class="actions"><button id="run" onclick="runWorker()">Run research cycle</button><button onclick="load()">Refresh</button></div>
</div>
<div class="grid">
<div class="card"><div class="metric" id="total">—</div><div class="muted">Findings</div></div>
<div class="card"><div class="metric" id="review">—</div><div class="muted">Awaiting review</div></div>
<div class="card"><div class="metric" id="submit">DISABLED</div><div class="muted">HackerOne submission</div></div>
</div>
<div class="card"><h2>Queue</h2><div id="list" class="muted">Loading…</div></div>
</main>
<script>
const TOKEN=__TOKEN__;
const SUBMIT=__SUBMIT__;
async function req(url,options){
  options=options||{};
  const headers=Object.assign({},options.headers||{},{"X-Action-Token":TOKEN});
  const r=await fetch(url,Object.assign({},options,{headers}));
  const t=await r.text(); let d; try{d=JSON.parse(t)}catch(e){d={detail:t}};
  if(!r.ok) throw new Error(d.detail||"Request failed"); return d;
}
function esc(v){return String(v).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[c]));}
async function load(){
  try{
    const d=await req("/api/findings"); const rows=d.findings||[];
    document.getElementById("total").textContent=rows.length;
    document.getElementById("review").textContent=rows.filter(x=>x.state==="needs_review"||x.state==="draft").length;
    document.getElementById("submit").textContent=SUBMIT?"ENABLED":"DISABLED";
    if(!rows.length){document.getElementById("list").innerHTML="<p class='muted'>No report candidates yet.</p>";return;}
    document.getElementById("list").innerHTML=rows.map(x=>{
      let b='<div class="finding card"><div style="display:flex;justify-content:space-between;gap:12px"><div><div class="title">'+esc(x.title||"Untitled")+'</div><div class="meta">'+esc(x.program_handle)+' · '+esc(x.target)+' · '+esc(x.severity||"review")+'</div></div><span class="badge">'+esc(x.state)+'</span></div>';
      b+='<div class="actions" style="margin-top:12px"><button onclick="view('+x.id+')">View report</button>';
      if((x.state==="needs_review"||x.state==="draft")&&SUBMIT)b+='<button class="primary" onclick="validateSubmit('+x.id+')">✓ Validate & Submit</button>';
      else if(x.state==="needs_review"||x.state==="draft")b+='<button class="primary" onclick="approve('+x.id+')">✓ Approve</button>';
      if(x.state==="approved"&&SUBMIT)b+='<button class="danger" onclick="submit('+x.id+')">Submit to HackerOne</button>';
      b+='</div><details id="d'+x.id+'"><summary>Evidence / report</summary><pre id="p'+x.id+'">Open to load…</pre></details></div>'; return b;
    }).join("");
  }catch(e){document.getElementById("list").innerHTML="<p>"+esc(e.message)+"</p>";}
}
async function view(id){const p=document.getElementById("p"+id);try{p.textContent=JSON.stringify(await req("/api/findings/"+id),null,2)}catch(e){p.textContent=e.message}document.getElementById("d"+id).open=true}
async function approve(id){if(!confirm("Confirm you personally validated scope, reproduction, evidence, duplicates and current program rules."))return;try{await req("/api/findings/"+id+"/approve",{method:"POST"});await load()}catch(e){alert(e.message)}}
async function submit(id){if(!confirm("Submit this already-approved report to HackerOne?"))return;try{const d=await req("/api/findings/"+id+"/submit",{method:"POST"});alert("Submitted. Report ID: "+(((d.report||{}).data||{}).id||"unknown"));await load()}catch(e){alert(e.message)}}
async function validateSubmit(id){if(!confirm("Confirm you personally reproduced the issue, verified current scope/rules, checked evidence and duplicates, and want to submit."))return;try{await req("/api/findings/"+id+"/approve",{method:"POST"});const d=await req("/api/findings/"+id+"/submit",{method:"POST"});alert("Submitted. Report ID: "+(((d.report||{}).data||{}).id||"unknown"));await load()}catch(e){alert(e.message)}}
async function runWorker(){const b=document.getElementById("run");b.disabled=true;try{alert(JSON.stringify(await req("/api/worker",{method:"POST"}),null,2));await load()}catch(e){alert(e.message)}finally{b.disabled=false}}
load();
</script>
</body>
</html>"""
    return (
        page.replace("__TOKEN__", json.dumps(token))
        .replace("__SUBMIT__", json.dumps(submit_enabled))
    )


@app.get("/health")
def health() -> JSONResponse:
    settings = Settings()
    store = Store(settings)
    try:
        return JSONResponse({
            "service": "h1-bounty-agent",
            "status": "online",
            "version": "0.4.0",
            "dry_run": settings.dry_run,
            "active_tests": settings.allow_active_tests,
            "autonomous_research": settings.autonomous_research,
            "submission_enabled": settings.enable_submission,
            "durable_storage": store.durable,
            "llm_provider": settings.llm_provider,
            "llm_available": LLMClient(settings).available(),
        })
    finally:
        store.close()
