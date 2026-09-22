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

## Current v0.8 — one-click full research & verification

- HackerOne Hacker API client
- Program discovery and structured-scope retrieval
- URL/domain/wildcard scope validation
- Local SQLite workspace for local runs
- Private Vercel Blob persistence for deployed findings
- Local Ollama LLM integration
- Hosted Hugging Face OpenAI-compatible LLM adapter
- Low-impact HTTP evidence collection
- One-click full research mode that runs the complete non-destructive research pipeline
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
- Deep business-logic and workflow-state modeling
- Authorized browser/HAR session trace analysis
- Object ownership and tenant-isolation modeling
- Role / privilege graph inference
- State-change mutation planning with explicit execution gate
- Attack hypothesis generation and evidence-driven test planning
- Recon surface change detection
- Persistent research memory
- Human review and approval gate
- One-click **Approve & Submit** workflow after human reproduction/validation
- Vercel Python/ASGI entrypoints
- Vercel daily discovery/research worker with explicit program allowlist
- Dashboard program selection with one-click full research per program
- Multi-surface scope routing for web, source-code, mobile, and cloud/IAM assets
- Bounded public source-repository/static artifact analysis when the asset itself is explicitly in scope
- Persistent background research jobs with progress tracking and evidence/check counts
- Optional two-authorized-account differential testing configuration
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

The scheduled worker remains discovery-first. The dashboard now exposes a single **Run Full Research** action per selected program. Full research runs the complete non-destructive research pipeline automatically: attack-surface discovery, workflow/business-logic modeling, hypothesis generation, CORS/reflection/redirect/error indicators, API/OpenAPI/GraphQL/WebSocket analysis, cloud/IAM indicators, attack-chain correlation, recon diffs, persistent research memory, and evidence-grounded LLM report drafting. This deep read-only research path does not depend on `ALLOW_ACTIVE_TESTS`. Two-account authorization testing is still opt-in with `ALLOW_AUTHZ_TESTS=true` and two explicitly supplied authorized test-account headers, and state-changing execution remains separately gated. All research remains structured-scope gated, does not submit forms or brute-force credentials, and never scans outside the selected HackerOne scope. Reports remain human-approved before submission. In the Render production Blueprint, `H1_ENABLE_SUBMISSION=true` means the dashboard's **Approve & Submit** action submits immediately after the approval gate succeeds; the backend still blocks submission unless the finding is approved, complete, in scope, and passes the existing validation checks.

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
AUTHZ_MAX_ENDPOINTS=30

# Full research breadth
FULL_RESEARCH_MAX_TARGETS_PER_PROGRAM=50
DEEP_MAX_SCRIPTS=30
DEEP_MAX_QUERY_LINKS=20
DEEP_MAX_API_CANDIDATES=30
DEEP_MAX_OPENAPI_STEPS=30
DEEP_MAX_GRAPHQL_ENDPOINTS=10
DEEP_MAX_WEBSOCKET_ENDPOINTS=10
SESSION_MAP_MAX_PAGES=40
SESSION_MAP_MAX_DEPTH=2
H1_ENABLE_SUBMISSION=true

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

- Render Postgres schema migration/retry hardening for long-lived deployments and dashboard queue reads.
## Render deployment

Vercel is not required for production hosting. This repository includes a Render Blueprint with a free FastAPI web service and Render Postgres, while scheduled research is triggered by GitHub Actions instead of a paid Render Cron Job.

The Render web service runs:

```text
uvicorn api.index:app --host 0.0.0.0 --port $PORT
```

Render Web Services deploy from a connected Git repository and expose an `onrender.com` URL. GitHub Actions triggers the existing `/api/cron` endpoint using two repository secrets: `H1_AGENT_URL` (the Render service URL) and `CRON_SECRET` (the matching Render secret). citeturn337425search3turn337425search1turn337425search2

To deploy:

1. Open Render and choose **New → Blueprint**.
2. Connect `PRADHUMAN-SINGH-1/h1-bounty-agent`.
3. Render reads `render.yaml` and provisions the web service and Postgres database.
4. Enter the prompted secrets: HackerOne API credentials, dashboard username/password, and your LLM provider credentials.
5. Open the generated `onrender.com` URL and use the existing H1 dashboard.

Scheduled research is configured in `.github/workflows/scheduled-research.yml` for daily discovery at 03:00 UTC. GitHub-hosted runners are free for public repositories, and scheduled workflows run from the default branch. citeturn684118search2turn684118search4

The application uses Postgres whenever `DATABASE_URL` is present, while local development without `DATABASE_URL` continues to use the JSON store. Render Blueprint `fromDatabase` wiring injects the database connection string without committing credentials to the repository. citeturn360941search0turn360941search4

`LLM_PROVIDER` must use a provider reachable from Render. The previous Vercel AI Gateway setting is not required for this deployment.

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

State-changing validation is separately gated by `ALLOW_STATE_CHANGING_TESTS=true` and should only be enabled for a program that explicitly permits the specific operation. The default behavior is to generate mutation plans without executing them.

Authorized browser traces can be analyzed locally:

```bash
h1-agent browser-analyze <handle> ./authorized-session.har
h1-agent business-model ./request-trace.json
```

The browser trace analyzer is scope-gated and is intended for exported, authorized traffic. It does not log in, submit forms, or obtain credentials itself.

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



## Open-source research toolchain

The deep runner can optionally use well-known open-source security tools when they are present on the GitHub Actions runner:

- ProjectDiscovery subfinder for passive subdomain discovery
- ProjectDiscovery httpx for HTTP probing and fingerprinting
- ProjectDiscovery katana for JavaScript-aware crawling
- ProjectDiscovery nuclei for template-driven vulnerability checks
- gau and waybackurls for historical URL discovery

The pipeline applies the HackerOne structured scope before tool output is admitted into research evidence. The runner is rate-limited and excludes intrusive/DoS Nuclei tags by default.

### GitHub Actions research runner

Full Research jobs are queued in Postgres and executed by .github/workflows/research-runner.yml rather than relying on a short-lived Render request.

Add these repository secrets in GitHub Actions:

- RESEARCH_DATABASE_URL — the Render Postgres connection string
- HACKERONE_USERNAME — HackerOne API token identifier
- HACKERONE_API_TOKEN — HackerOne API token value
- HF_TOKEN — Hugging Face inference token

The default runner keeps ALLOW_ACTIVE_TESTS=false, ALLOW_AUTHZ_TESTS=false, and H1_ENABLE_SUBMISSION=false.

### Submission

The system remains evidence-gated: a report is only submitted after scope and completeness validation. Blind automatic submission is not enabled by default.
