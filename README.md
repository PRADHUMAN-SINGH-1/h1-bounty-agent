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

## Current v0.3

- HackerOne Hacker API client
- Program discovery and structured-scope retrieval
- URL/domain/wildcard scope validation
- Local SQLite workspace for local runs
- Local Ollama LLM integration
- Low-impact HTTP evidence collection
- Evidence-grounded finding drafting
- Human review and approval gate
- Explicit submission gate
- Vercel Python/ASGI entrypoints
- Vercel daily discovery cron
- GitHub Actions CI

## Vercel deployment

The repository now includes:

- `api/index.py` → health endpoint
- `api/programs.py` → authenticated HackerOne program endpoint
- `api/cron.py` → scheduled program/scope triage worker
- `vercel.json` → Vercel Function + Cron configuration

After Vercel rebuilds from the latest `main` commit:

- `/api` returns service health.
- `/api/programs` checks the HackerOne API.
- `/api/cron` performs the scheduled program/scope triage.

The cron worker is currently **discovery-only**. It does not autonomously attack targets or submit reports. That is intentional while the research and durable-state layers are being hardened.

Current Vercel scheduling depends on the plan: Hobby currently provides daily Cron execution with per-hour precision, while Pro/Enterprise support more frequent scheduling.

## Environment variables

Configure these in the Vercel project environment settings rather than GitHub:

```text
HACKERONE_USERNAME=<API token identifier>
HACKERONE_API_TOKEN=<API token value>
HACKERONE_BASE_URL=https://api.hackerone.com

DRY_RUN=true
ALLOW_ACTIVE_TESTS=false
H1_ENABLE_SUBMISSION=false

# Optional cron protection
CRON_SECRET=<random secret>

# Local-only LLM settings
LLM_PROVIDER=ollama
LLM_BASE_URL=http://127.0.0.1:11434
LLM_MODEL=llama3.1:8b
```

**Never commit HackerOne credentials.**

The current GitHub/Vercel architecture does not require a paid LLM for local development, but Vercel itself cannot run your Mac's local Ollama process. A hosted LLM or separate compute layer will be needed before the deployed agent can perform LLM-based research automatically.

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

## Human validation

**AI / automation:** program discovery, scope loading, research planning, low-impact evidence collection, evidence-grounded draft generation, report formatting.

**You:** review current program rules, reproduce the behavior, confirm scope, verify impact/evidence, check duplicates/exclusions, confirm severity, and approve the report.

HackerOne currently requires a human-in-the-loop for AI-assisted Hackbot activity and states that the researcher remains responsible for submissions.

## Zero-cash starting point

The initial system is designed to avoid per-request LLM costs during local development by using a local model. The deployed Vercel worker can run scheduled HackerOne discovery without an LLM, but the full AI research layer requires hosted inference or another compute environment.

This project does **not** guarantee bounty income. A finding must be real, reproducible, in scope, eligible, sufficiently demonstrated, and accepted by the program.

## Roadmap

1. Program and scope intelligence ✅
2. Low-impact research engine ✅
3. Evidence-grounded LLM finding draft ✅
4. Human validation gate ✅
5. Submission gate ✅
6. Vercel health/API endpoints ✅
7. Vercel scheduled discovery ✅
8. Durable cloud finding storage
9. Authorization-aware research plugins
10. Duplicate/history correlation
11. Earnings/report-state synchronization
12. Hosted LLM worker
13. Background research scheduler
