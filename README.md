# H1 Bounty Agent

AI-assisted HackerOne research workspace designed to automate the repetitive parts of authorized bug-bounty research while keeping the required human validation gate.

## Architecture

```text
HackerOne API
     ↓
Program discovery
     ↓
Scope / policy gate
     ↓
Research checks
     ↓
Evidence
     ↓
LLM analysis
     ↓
Human validation
     ↓
Explicit approval
     ↓
Optional HackerOne submission
```

The project is intentionally **fail-closed**. A target must match an eligible structured scope before the research engine can send target traffic.

## Current v0.6 — deep research & verification

- HackerOne Hacker API client
- Program discovery and structured-scope retrieval
- URL/domain/wildcard scope validation
- Local SQLite workspace for local runs
- Private Vercel Blob persistence for deployed findings
- Local Ollama LLM integration
- Hosted Hugging Face OpenAI-compatible LLM adapter
- Low-impact HTTP evidence collection
- Scope-gated deep vulnerability assessment mode
- Same-origin link/query/JavaScript attack-surface discovery without form submission
- OpenAPI/Swagger GET-operation extraction
- Read-only endpoint inventory for discovered API surfaces
- Reflection canary checks, credentialed CORS differential checks, redirect-parameter checks, cookie flag checks, source-map checks, API-spec discovery, and mixed-content observations
- Optional two-account read-only authorization differential testing
- Evidence-grounded finding drafting
- Authenticated read-only session/workflow mapping
- IDOR/BOLA object differential testing with two authorized test accounts
- Role/permission differential modeling
- Stateful read-only API workflow traversal
- GraphQL introspection analysis
- WebSocket endpoint discovery and handshake checks
- Mobile APK/IPA static surface analysis
- Cloud/IAM footprint and policy analysis
- Attack-chain correlation
- Human review and approval gate
- Explicit submission gate
- Vercel Python/ASGI entrypoints
- Vercel daily discovery/research worker with explicit program allowlist
- Dashboard program selection with human authorization for low-impact passive research
- Authenticated web review dashboard with one-click Validate & Submit
- GitHub Actions CI

## Vercel deployment

The repository now includes:

- `api/index.py` → health endpoint
- `index.py` → authenticated web review dashboard
- `api/programs.py` → authenticated HackerOne program endpoint
- `api/findings.py` → finding review/approval/submission API
- `api/worker.py` → authenticated on-demand research cycle
- `api/cron.py` → scheduled worker
- `vercel.json` → Vercel Function + Cron configuration

After Vercel rebuilds from the latest `main` commit:

- `/api` returns service health.
- `/api` returns service health.
- `/api/programs` checks the HackerOne API after dashboard authentication.
- `/api/findings` exposes the private review queue after dashboard authentication.
- `/api/cron` runs the scheduled worker and requires `CRON_SECRET`.
- `/api/worker` runs one on-demand cycle after dashboard authentication.
- `/` opens the review dashboard.

The cron worker supports discovery and an optional passive-research mode. Discovery runs automatically. Passive research can be enabled with `AUTONOMOUS_PASSIVE_RESEARCH=true` plus an explicit `RESEARCH_PROGRAM_ALLOWLIST`; it performs only the low-impact checks implemented in the research engine. Deep vulnerability assessment is explicitly user-triggered and separately gated by `ALLOW_ACTIVE_TESTS=true`. Two-account authorization testing is an additional opt-in with `ALLOW_AUTHZ_TESTS=true` and two explicitly supplied test-account headers. The assessment engine remains scope-gated and uses non-destructive GET/OPTIONS-style probes; it does not submit forms, brute-force credentials, exploit destructive payloads, or scan outside the selected HackerOne structured scope. Neither mode submits reports automatically.

Current Vercel scheduling depends on the plan: Hobby currently provides daily Cron execution with per-hour precision, while Pro/Enterprise support more frequent scheduling.

## Environment variables

Configure these in the Vercel project environment settings rather than GitHub:

```text
HACKERONE_USERNAME=<API token identifier>
HACKERONE_API_TOKEN=<API token value>
HACKERONE_BASE_URL=https://api.hackerone.com

DRY_RUN=true
ALLOW_ACTIVE_TESTS=false
ALLOW_AUTHZ_TESTS=false
AUTHZ_HEADER_A=Authorization: Bearer <test-account-A-token>
AUTHZ_HEADER_B=Authorization: Bearer <test-account-B-token>
AUTHZ_MAX_ENDPOINTS=12
SESSION_MAP_MAX_PAGES=40
SESSION_MAP_MAX_DEPTH=2
H1_ENABLE_SUBMISSION=false

# Optional cron protection
CRON_SECRET=<random secret>

# Durable deployed storage
BLOB_READ_WRITE_TOKEN=<private Vercel Blob credential>

# Dashboard authentication
DASHBOARD_USER=<username>
DASHBOARD_PASSWORD=<strong password>
DASHBOARD_SECRET=<random secret>

# Hosted LLM for Vercel
LLM_PROVIDER=vercel_gateway
LLM_BASE_URL=https://ai-gateway.vercel.sh/v1
LLM_MODEL=inclusionai/ling-3.0-flash-vl-free
# Production Vercel OIDC is preferred; enable "Secure Backend Access with OIDC Federation".

# Local-only alternative
LLM_PROVIDER=ollama
LLM_BASE_URL=http://127.0.0.1:11434
LLM_MODEL=llama3.1:8b

# Autonomous research gates
AUTONOMOUS_RESEARCH=false
AUTONOMOUS_PASSIVE_RESEARCH=false
AUTONOMOUS_MAX_PROGRAMS=3
AUTONOMOUS_MAX_TARGETS_PER_PROGRAM=2
RESEARCH_PROGRAM_ALLOWLIST=<reviewed handles, comma separated>
```

****Blank environment values are handled safely:** numeric settings such as `REQUESTS_PER_SECOND` fall back to defaults instead of crashing a serverless function.

Never commit HackerOne credentials.**

Vercel cannot run your Mac's local Ollama process. The production configuration now prefers Vercel AI Gateway with Vercel OIDC; Vercel documents OIDC authentication for AI Gateway, and its catalog includes free models. citeturn107218search3turn408691search1

## Local workflow

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[test]'
cp .env.example .env
```

Discover programs:

```bash
h1-agent discover --limit 15
```

Inspect a program:

```bash
h1-agent program <handle>
```

Generate an AI plan locally with Ollama:

```bash
h1-agent plan <handle>
```

Check a target without sending target traffic:

```bash
h1-agent dry-run <handle> https://target.example/
```

Run the low-impact research engine only after reviewing the program policy and enabling the local gate:

```text
ALLOW_ACTIVE_TESTS=true
```

Then:

```bash
h1-agent research <handle> https://target.example/ --active
```

Review:

```bash
h1-agent findings
h1-agent review <finding-id>
```

Approve only after personally validating the finding:

```bash
h1-agent approve <finding-id>
```

Submission remains separately disabled until explicitly enabled.

Additional local analysis commands:

```bash
h1-agent mobile-analyze ./app.apk
h1-agent mobile-analyze ./app.ipa
h1-agent cloud-analyze ./policy.json
h1-agent capabilities
```

Two-account authorization testing requires `ALLOW_AUTHZ_TESTS=true` plus two test-account headers. The tool performs read-only differential checks and still requires human reproduction before a report can be approved.

## Human validation

**AI / automation:** program discovery, scope loading, research planning, low-impact evidence collection, evidence-grounded draft generation, report formatting.

**You:** review current program rules, reproduce the behavior, confirm scope, verify impact/evidence, check duplicates/exclusions, confirm severity, and approve the report.

HackerOne currently requires a human-in-the-loop for AI-assisted Hackbot activity and states that the researcher remains responsible for submissions.

## Zero-cash starting point

The initial system is designed to avoid per-request LLM costs during local development by using a local model. The deployed Vercel worker can run scheduled HackerOne discovery without an LLM. When the Hugging Face provider is configured and authorized research is enabled, it can also draft evidence-grounded report candidates.

This project does **not** guarantee bounty income. A finding must be real, reproducible, in scope, eligible, sufficiently demonstrated, and accepted by the program.

## Roadmap

1. Program and scope intelligence ✅
2. Low-impact research engine ✅
3. Evidence-grounded LLM finding draft ✅
4. Human validation gate ✅
5. Submission gate ✅
6. Vercel health/API endpoints ✅
7. Vercel scheduled discovery ✅
8. Duplicate/history correlation
9. Earnings/report-state synchronization
10. More authorization-aware research plugins
11. Deeper evidence correlation and report quality scoring
12. Authenticated two-account authorization testing where a program explicitly permits it ✅
13. Authenticated workflow mapping ✅
14. Stateful read-only API workflows ✅
15. GraphQL/WebSocket coverage ✅
16. Mobile/cloud static analysis ✅
17. Broader state-changing business-logic tests remain intentionally gated to explicit program authorization and human validation
