from __future__ import annotations

import html
import json

from fastapi import FastAPI
from fastapi.responses import HTMLResponse

from h1_agent.config import Settings
from h1_agent.web_auth import action_token

app = FastAPI(title="H1 Bounty Agent", version="0.4.0")


@app.get("/", response_class=HTMLResponse)
def dashboard() -> str:
    settings = Settings()
    settings.require_dashboard_credentials()
    token = action_token(settings.dashboard_secret)
    submit_enabled = settings.enable_submission

    page = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>H1 Bounty Agent</title>
<style>
:root{color-scheme:dark;--bg:#070b12;--panel:#0e1522;--line:#21314b;--text:#e9f0fb;--muted:#8fa3bf;--accent:#70e1c1;--danger:#ff7b8a}
*{box-sizing:border-box}
body{margin:0;font-family:Inter,system-ui,sans-serif;background:radial-gradient(circle at top right,#102033 0,#070b12 45%);color:var(--text)}
.wrap{max-width:1180px;margin:0 auto;padding:32px 20px 70px}
.header{display:flex;justify-content:space-between;gap:20px;align-items:flex-start;margin-bottom:26px}
h1{margin:0;font-size:32px;letter-spacing:-.03em}.sub{color:var(--muted);margin-top:7px}
.grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;margin:22px 0}
.card{background:linear-gradient(180deg,#111b2b,var(--panel));border:1px solid var(--line);border-radius:18px;padding:18px;box-shadow:0 12px 35px rgba(0,0,0,.18)}
.metric{font-size:26px;font-weight:700}.label{color:var(--muted);font-size:13px;margin-top:4px}
.actions{display:flex;gap:10px;flex-wrap:wrap}
button{border:1px solid var(--line);background:#15243a;color:var(--text);padding:10px 14px;border-radius:10px;cursor:pointer;font-weight:650}
button.primary{background:var(--accent);color:#06110d;border-color:transparent}
button.danger{background:var(--danger);color:#21070b;border-color:transparent}
button:disabled{opacity:.5;cursor:not-allowed}
.finding{margin-top:14px}.top{display:flex;justify-content:space-between;gap:14px;align-items:flex-start}
.title{font-size:19px;font-weight:750}.meta{color:var(--muted);font-size:13px;margin-top:5px}
.badge{display:inline-flex;padding:4px 8px;border-radius:999px;background:#17263d;border:1px solid var(--line);font-size:12px}
pre{white-space:pre-wrap;overflow:auto;background:#07101d;border:1px solid var(--line);border-radius:12px;padding:14px;color:#cbd8eb}
.small{font-size:12px;color:var(--muted)}.error{color:#ff7b8a}
@media(max-width:800px){.grid{grid-template-columns:1fr}.header{flex-direction:column}}
</style>
</head>
<body>
<div class="wrap">
<div class="header">
<div><h1>H1 Bounty Agent</h1><div class="sub">Authorized research → evidence → human validation → HackerOne submission</div></div>
<div class="actions"><button id="run" onclick="runWorker()">Run research cycle</button><button onclick="loadFindings()">Refresh</button></div>
</div>
<div class="grid">
<div class="card"><div class="metric" id="total">—</div><div class="label">Findings</div></div>
<div class="card"><div class="metric" id="review">—</div><div class="label">Awaiting review</div></div>
<div class="card"><div class="metric" id="submitmode">SUBMIT</div><div class="label">HackerOne submission</div></div>
</div>
<div class="card">
<div class="top"><div><div class="title">Queue</div><div class="small">Findings are private when Vercel Blob is configured as private storage.</div></div><span class="badge">v0.4</span></div>
<div id="list"><div class="small">Loading…</div></div>
</div>
</div>
<script>
const ACTION_TOKEN = __ACTION_TOKEN__;
const SUBMIT_ENABLED = __SUBMIT_ENABLED__;

async function request(url, options) {
  options = options || {};
  const headers = Object.assign({}, options.headers || {}, {"X-Action-Token": ACTION_TOKEN});
  const res = await fetch(url, Object.assign({}, options, {headers: headers}));
  const text = await res.text();
  let data;
  try { data = JSON.parse(text); } catch(e) { data = {detail:text}; }
  if (!res.ok) throw new Error(data.detail || "Request failed");
  return data;
}
function esc(value) {
  return String(value).replace(/[&<>"']/g, function(c) {
    return {"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[c];
  });
}
async function loadFindings() {
  const root = document.getElementById("list");
  try {
    const data = await request("/api/findings");
    const rows = data.findings || [];
    document.getElementById("total").textContent = rows.length;
    document.getElementById("review").textContent = rows.filter(function(x){return x.state==="needs_review" || x.state==="draft";}).length;
    document.getElementById("submitmode").textContent = SUBMIT_ENABLED ? "ENABLED" : "DISABLED";
    if (!rows.length) { root.innerHTML = '<div class="small">No report candidates yet.</div>'; return; }
    root.innerHTML = rows.map(function(row) {
      var html = '<div class="finding card">';
      html += '<div class="top"><div><div class="title">'+esc(row.title || "Untitled candidate")+'</div>';
      html += '<div class="meta">'+esc(row.program_handle)+' · '+esc(row.target)+' · '+esc(row.severity || "review")+'</div></div>';
      html += '<span class="badge">'+esc(row.state)+'</span></div>';
      html += '<div class="actions" style="margin-top:14px">';
      html += '<button onclick="viewFinding('+row.id+')">View report</button>';
      if (row.state === "needs_review" || row.state === "draft") html += '<button class="primary" onclick="approveFinding('+row.id+')">✓ Approve</button>';
      if (row.state === "approved" && SUBMIT_ENABLED) html += '<button class="danger" onclick="submitFinding('+row.id+')">Submit to HackerOne</button>';
      html += '</div><details id="detail-'+row.id+'"><summary>Evidence / report</summary><pre id="pre-'+row.id+'">Open to load…</pre></details></div>';
      return html;
    }).join("");
  } catch (err) { root.innerHTML = '<div class="error">'+esc(err.message)+'</div>'; }
}
async function viewFinding(id) {
  const pre = document.getElementById("pre-"+id);
  try { pre.textContent = JSON.stringify(await request("/api/findings/"+id), null, 2); }
  catch (err) { pre.textContent = err.message; }
  const detail = document.getElementById("detail-"+id); if (detail) detail.open = true;
}
async function approveFinding(id) {
  if (!confirm("Confirm that you personally validated the finding, scope, evidence, reproduction and current program rules. Approve?")) return;
  try { await request("/api/findings/"+id+"/approve",{method:"POST"}); await loadFindings(); }
  catch (err) { alert(err.message); }
}
async function submitFinding(id) {
  if (!confirm("Submit this already-approved report to HackerOne?")) return;
  try {
    const data = await request("/api/findings/"+id+"/submit",{method:"POST"});
    alert("Submitted. HackerOne report ID: "+((((data||{}).report||{}).data||{}).id || "unknown"));
    await loadFindings();
  } catch (err) { alert(err.message); }
}
async function runWorker() {
  const btn=document.getElementById("run"); btn.disabled=true; btn.textContent="Running…";
  try { alert(JSON.stringify(await request("/api/worker",{method:"POST"}),null,2)); await loadFindings(); }
  catch (err) { alert(err.message); }
  finally { btn.disabled=false; btn.textContent="Run research cycle"; }
}
loadFindings(); setInterval(loadFindings,30000);
</script>
</body>
</html>"""
    page = page.replace("__ACTION_TOKEN__", json.dumps(token))
    page = page.replace("__SUBMIT_ENABLED__", json.dumps(submit_enabled))
    return HTMLResponse(content=page)
