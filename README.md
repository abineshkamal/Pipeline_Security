# PipelineTrust — AI-Powered CI/CD Security Assurance

PipelineTrust assesses CI/CD pipelines (GitHub Actions first) against the **OWASP Top 10 CI/CD Security Risks**.
Deterministic rules and external scanners establish every finding; LangGraph AI agents only annotate,
prioritise and explain them, and a guardrail discards any AI reference to a finding or path that does not exist.

## What it does

| Capability | Implementation |
|---|---|
| Asset discovery | GitHub connector (read-only REST API + zipball): repo inventory, workflows, branch protection, rulesets, environments, token defaults, Actions policy, collaborators. Offline ZIP upload. Connector registry with GitLab / Bitbucket / Azure DevOps / Jenkins placeholders. |
| Deterministic scanner | 47 controls in `backend/app/scanner/rules/` (one module per OWASP category, auto-registered). Line-accurate evidence, redacted secrets, PASS / FAIL / NOT ASSESSED / NOT APPLICABLE / NEEDS MANUAL VALIDATION. |
| External tools | gitleaks, trufflehog (no live verification), actionlint, zizmor, trivy (vuln + misconfig), syft (SBOM), grype; checkov / kics adapters. Safe subprocess (no shell, timeout, scrubbed env). Missing tool → dependent controls NOT ASSESSED. Tool findings that match a built-in finding are merged in as corroborating evidence. |
| Attack paths | networkx graph actor → trigger → job → capability (secrets, write token, OIDC, self-hosted runner, deploy) → impact. Every entry edge references a finding. Optional Neo4j mirror. |
| AI agents (LangGraph) | context analyst → triage analyst → attack-path analyst → remediation engineer → report writer → guardrail. Providers: Anthropic Claude (default `claude-opus-5-5`), OpenAI, or none (deterministic fallback). |
| Platform | JWT auth, organizations, Admin / Analyst / Viewer RBAC, tenant isolation (cross-org lookups return 404), Fernet-encrypted credentials, audit log, login throttling, security headers/CSP. |
| Reporting | HTML (self-contained, printable), JSON, SARIF 2.1.0 (GitHub code scanning), CycloneDX SBOM; posture trend, scan comparison (new / fixed / persisting), triage carried across re-scans. |
| CLI / CI gate | `python -m app.cli scan PATH --format sarif --fail-on high [--policies DIR --fail-on-policy] [--max-attack-paths 0] [--summary FILE]`, or the bundled GitHub Action (see `examples/pipelinetrust-gate.yml`). |

## Remediation, insight and governance features

| Feature | Where | What it does |
|---|---|---|
| Pipeline view | Project page → Pipelines | One row per workflow file (riskiest first); each opens a per-pipeline analysis with its findings, jobs, actions, secrets, attack paths and fixes. |
| One-click fixes | Scan / pipeline → Fix & simulate | Rule-based patches for PT-3P-001 (pin to commit SHA), PT-PBAC-001 (read-only `permissions:`), PT-CRED-005 (`persist-credentials: false`) and PT-PPE-003 (untrusted `${{ }}` moved to `env:`). Each patched file is re-parsed and every workflow rule re-run; only verified fixes are offered. Download a `.patch` or open a pull request (needs a separate token with Contents + Pull requests write). Actions with an advisory are never auto-pinned. |
| What-if simulator | Scan / pipeline → Fix & simulate | Mark findings as fixed and see the recomputed posture score, controls and attack paths (same scoring code as a scan); ranks whole-rule and single fixes by paths removed and score gained. |
| Secret blast radius | Scan / pipeline → Secrets | Per secret: pipelines and jobs that read it, who can trigger them (outsiders via privileged triggers, contributors, maintainers), environment gates and attacker-influenced code in the same job. |
| Compromised-action watch | Threat watch | Built-in advisories (CVE-2025-30066, CVE-2025-30154) plus organization advisories, matched against every project's latest inventory without re-scanning; lists GitHub Actions runs inside the incident window. |
| Compliance evidence packs | Scan → Compliance | Indicative mapping of controls to NIST SSDF, SLSA Build track, CIS Software Supply Chain areas, SOC 2 and ISO/IEC 27001:2022, with evidence; export HTML, CSV or JSON. |
| Ask your pipelines | Scan → Ask | Questions answered from scan data: deterministic intents always; with an LLM configured, answers must cite ids and a guardrail removes any reference that does not exist. |
| Organization portfolio | Portfolio | Import every repository of a GitHub organization or user (skips archived / forks unless asked, never duplicates), then a risk leaderboard (riskiest first) with score trend, attack paths, outsider-reachable and stale secrets, exceptions and alerts, a per-owner roll-up, and bulk scan / schedule. |
| Scheduled scans + drift alerts | Project page, Portfolio, Alerts | Daily or weekly re-scans. Every completed scan is compared with the previous one; only regressions alert (new attack path, new critical/high finding, secret newly reachable by outsiders, score drop). Delivered to Slack, Microsoft Teams (workflow webhook, Adaptive Card) or a generic JSON webhook, filtered by minimum severity. Webhook URLs are encrypted; HTTPS only and private / loopback addresses are refused. |
| Risk exceptions | Finding detail, Exceptions | Accept a finding, a rule in one workflow or a rule in a project with a justification, compensating controls, a risk owner and an expiry (max 365 days). An admin other than the requester must approve. Active exceptions mark findings `accepted risk` on every scan; on expiry or revocation the findings reopen. The posture score is not changed. |
| Secret rotation | Scan / pipeline → Secrets | With a token that has `Secrets: read` (names and dates only), shows when each secret was last updated (environment > repository > organization, as GitHub injects them), flags aging (90+ days) and stale (180+ days) secrets and lists "rotate first": highly exposed and old. |
| Release / change diff | Project → Scans → tick two → Compare | Scan any branch, tag or commit (`ref`), then compare two scans: pipelines, triggers, job permissions, secrets, runners, environments and third-party actions added / removed / re-pinned, classified riskier / safer, plus new and removed attack paths and findings. Ref scans never become the project's current posture, raise drift alerts or close tickets. |
| Attacker walkthrough | Scan → Attack paths | For each attack path, the attacker's steps with the evidence behind each one, the defence at each step, and the fixes that break the chain (single findings or a whole step), verified with the what-if simulator. |
| Runtime evidence | Scan / pipeline → Runtime | Reads the last 300 GitHub Actions runs: privileged workflows actually started from forks or by non-members ("observed in practice"), dormant pipelines that still hold secrets, run counts, events and failure rates. Self-hosted runner and runner-group inventory (needs Administration read / org admin) cross-referenced with fork-reachable jobs. |
| Executive report | Portfolio → Executive report | Printable one-page report for 30 to 365 days: posture trend, riskiest projects and teams, most common weaknesses, fixed vs new findings, drift alerts and expiring exceptions. |
| Jira / ServiceNow tickets | Settings → Ticketing, finding detail | Open a ticket from any finding; tickets follow the finding fingerprint across scans, get a comment and an optional close transition / state when a scan no longer finds it, and reopen in PipelineTrust if it comes back. Credentials encrypted, HTTPS only. |
| CI gate (GitHub Action) | `action.yml`, `examples/pipelinetrust-gate.yml` | Composite action: installs the CLI (`backend/requirements-cli.txt`), fails on severity, on custom-policy violations (`--policies`, `--fail-on-policy`) or on more attack paths than allowed (`--max-attack-paths`), writes SARIF and a job summary. Inputs are passed as environment variables, never interpolated. |
| Least-privilege permissions | Pipeline → Jobs & permissions; the PT-PBAC-001 auto-fix | Infers each job's minimum GITHUB_TOKEN scopes from known actions and `gh` / `git` usage, with reasons and a confidence level. The auto-fix adds `contents: read` at workflow level plus exact job-level blocks, and never grants write scopes to workflows that pull requests or comments can trigger (it explains how to split them instead). |
| Fix campaigns | Portfolio → Fix campaigns | Roll an auto-fixable rule out to many repositories as verified pull requests (dry run first), then follow each PR to merge and confirm with re-scans. Needs a separate token with Contents + Pull requests write. |
| Action reputation + allowlist | Supply chain → Action reputation / Allowlist | Scores every third-party action in use (publisher verification, maintenance, age, popularity, archived, advisories; GitHub metadata cached 24 h) and generates the GitHub "allowed actions" policy JSON (optionally exact SHAs) with the `gh api` commands to apply it. |
| Remediation SLAs | Portfolio → Remediation SLAs | Per-severity targets (default 7 / 30 / 90 / 180 days), open and overdue findings, mean time to fix and percentage fixed within target, by severity and team. |
| API tokens | Settings → API tokens | `pt_…` keys for scripts and CI: role-scoped, capped at the creator's current role, bound to one organization, expiring, revocable, stored as SHA-256; tokens cannot create tokens or open campaign PRs. |
| SIEM export | Settings → SIEM export | Streams audit events and drift alerts to Splunk HEC, Datadog logs or an HMAC-signed webhook in the background; JSONL audit export for backfill. |
| Plain-English policies | Policies → Describe a rule | Drafts a policy from a sentence (AI provider if configured, otherwise built-in templates), validates it with the policy parser and dry-runs it on every project before you save it. |
| Golden templates | Policies → Golden pipeline templates | Mark an approved (reusable) workflow and see which repositories call it, call an unapproved version, copied it, drifted from it (missing / extra steps) or never adopted it. |
| Policies (policy-as-code) | Policies | Organization rules in YAML over workflows, jobs or actions (`when` / `unless` conditions); dry-run against every project, then evaluated on every scan like a built-in rule. |

## OWASP CI/CD coverage

| Category | Rules |
|---|---|
| CICD-SEC-1 Flow control | PT-FC-001 branch protection · 002 required reviews · 003 deploy without environment protection · 004 automation can approve/merge |
| CICD-SEC-2 IAM | PT-IAM-001 CODEOWNERS for workflows · 002 admin sprawl · 003 org 2FA |
| CICD-SEC-3 Dependency chain | PT-DEP-001 untrusted sources (curl\|sh, http index, extra-index-url, TLS off) · 002 non-lockfile installs · 003 missing lockfiles · 004 vulnerable deps (trivy/grype) |
| CICD-SEC-4 PPE | PT-PPE-001 privileged trigger + untrusted checkout · 002 pull_request_target/workflow_run usage · 003 script injection · 004 workflow_run artifact poisoning · 005 PR code with secrets/write |
| CICD-SEC-5 PBAC | PT-PBAC-001 missing permissions · 002 excessive permissions · 003 workflow-wide deploy scopes · 004 `secrets: inherit` · 005 repo default token write |
| CICD-SEC-6 Credentials | PT-CRED-001 hard-coded secrets · 002 secrets in untrusted contexts · 003 toJSON(secrets)/inline secrets · 004 static cloud keys vs OIDC · 005 persisted checkout token · 006 secrets in repo (gitleaks/trufflehog) |
| CICD-SEC-7 System config | PT-SYS-001 self-hosted runner exposure · 002 privileged containers/docker.sock/unsecure commands · 003 actionlint · 004 unparseable workflows · 005 IaC misconfig |
| CICD-SEC-8 Third party | PT-3P-001 unpinned actions · 002 unpinned images · 003 allowed-actions policy · 004 known compromised actions · 005 publisher inventory |
| CICD-SEC-9 Artifact integrity | PT-ART-001 SBOM · 002 signing · 003 provenance · 004 verification on consumption · 005 cache poisoning |
| CICD-SEC-10 Logging | PT-LOG-001 audit-log streaming (manual) · 002 short retention · 003 silenced security checks · 004 no security scanning |
| Cross-category | PT-TOOL-ZIZMOR (findings mapped to their category) |

## Run locally (no Docker)

```bash
cd backend
python -m venv .venv && .venv/Scripts/pip install -r requirements-dev.txt   # (bin/ on Linux/macOS)
cd ../frontend && npm ci && npm run build                                  # static export -> frontend/out
cd ../backend
PT_TOOLS_DIR=/path/to/scanner/binaries PT_FRONTEND_DIR=../frontend/out .venv/Scripts/python -m uvicorn app.main:app --port 8000
```
Open http://127.0.0.1:8000, register an organization, create a project (GitHub repo or ZIP upload), run a scan.
Without `PT_DATABASE_URL` / `PT_REDIS_URL` / `PT_NEO4J_URI` it uses SQLite, an in-process job pool and the in-memory graph.
API docs: `/api/docs`.

Monitoring: the scheduler runs inside the API process (`PT_SCHEDULER_ENABLED=true`, checks every `PT_SCHEDULER_INTERVAL_SECONDS`); run it on one
instance only. Set `PT_PUBLIC_URL` so alerts link back to the scan.

AI agents: set `PT_LLM_PROVIDER=anthropic` and `PT_ANTHROPIC_API_KEY=…` (or `openai` + `PT_OPENAI_API_KEY`).

## Deploy on Railway

The repo is Railway-ready (`railway.json` + `Dockerfile`; the app listens on `$PORT`, accepts Railway's `postgresql://` URL and fixes volume ownership at startup).

1. **New Project → Deploy from GitHub repo** → select this repository. Railway builds the `Dockerfile`.
2. **+ New → Database → PostgreSQL**.
3. On the app service → **Settings → Volumes**: add a volume mounted at **`/data`** (uploads, SBOMs, scanner caches).
4. On the app service → **Variables**:

   | Variable | Value |
   |---|---|
   | `PT_DATABASE_URL` | `${{Postgres.DATABASE_URL}}` |
   | `PT_JWT_SECRET` | output of `python -c "import secrets;print(secrets.token_urlsafe(48))"` |
   | `PT_ENCRYPTION_KEY` | output of `python -c "from cryptography.fernet import Fernet;print(Fernet.generate_key().decode())"` — keep a backup |
   | `PT_LLM_PROVIDER` / `PT_ANTHROPIC_API_KEY` | optional, enables the AI agents |

5. **Settings → Networking → Generate Domain**, then open it and register your organization.

Scans run inside the app service by default. To scale scanning, add a Redis database, set `PT_REDIS_URL=${{Redis.REDIS_URL}}`
on the app, and add a second service from the same repo with start command `python -m app.worker`, the same variables and the same volume.
Neo4j is optional (`PT_NEO4J_URI` etc.); the attack graph works without it.

## Run with Docker Compose

```bash
cp .env.example .env        # fill in the secrets
docker compose up -d --build
```
Services: `api` (FastAPI + static UI + scanner binaries), `worker` (Redis queue consumer), `postgres`, `redis`, `neo4j`.
Containers run as non-root, read-only, all capabilities dropped. Put a TLS reverse proxy in front of port 8000.

## Tests

```bash
cd backend && .venv/Scripts/python -m pytest -q          # 83 tests: rules, YAML/ZIP safety, API/RBAC/isolation, reports, agents, Redis worker, insights, monitoring, analysis, CLI gate, enterprise features
.venv/Scripts/python scripts/smoke_scan.py gitleaks,actionlint,zizmor,trivy,syft   # full engine on the sample repos
.venv/Scripts/python scripts/e2e_browser.py http://127.0.0.1:8000 shots           # browser E2E (installed Microsoft Edge via Playwright)
```
`samples/vulnerable-repo` deliberately fails all ten categories; `samples/hardened-repo` must produce zero failing controls.

## Adding a rule

Create a class in any module under `backend/app/scanner/rules/` (or a new module):

```python
from ..model import WorkflowRule

class MyRule(WorkflowRule):
    id = "PT-PPE-099"; category = "CICD-SEC-4"; title = "…"; description = "…"; severity = "high"
    cwe = ["CWE-94"]; remediation = "…"; evidence_requirements = "…"; false_positives = "…"
    def check(self, ctx, wf):
        return [self.finding("message", wf=wf, job=job, line=job.line) for job in wf.jobs if …]
```
It is registered on import; the engine, API, UI catalog and reports pick it up with no other change.

## Security design notes

* Repository code is never executed. Archives are extracted with zip-slip, symlink, size and file-count guards, and deleted after the scan.
* YAML is parsed with `SafeLoader` and alias-bomb protection; malformed files are reported as a coverage gap.
* GitHub tokens are encrypted with Fernet (`PT_ENCRYPTION_KEY`), never returned by the API, and only sent to `api.github.com` (not to the archive download host).
* Recommended token: fine-grained, read-only (Contents, Metadata, Actions, Administration, Environments; add Secrets for rotation dates). `Test` in Settings warns about classic write scopes.
* Prompts mark repository content as untrusted; AI output is schema-validated and cannot change control status.

## Known limitations

* Only GitHub Actions is assessed; other CI files are detected and reported as NOT ASSESSED.
* Organization-level controls (audit-log streaming, SSO) need manual validation; several repository settings need an admin-capable token.
* Absence-based controls (SBOM, signing, provenance) are indicators: signing done outside the workflow cannot be seen.
