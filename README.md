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
| CLI / CI gate | `python -m app.cli scan PATH --format sarif --fail-on high` (see `examples/pipelinetrust-ci.yml`). |

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

AI agents: set `PT_LLM_PROVIDER=anthropic` and `PT_ANTHROPIC_API_KEY=…` (or `openai` + `PT_OPENAI_API_KEY`).

## Run with Docker Compose

```bash
cp .env.example .env        # fill in the secrets
docker compose up -d --build
```
Services: `api` (FastAPI + static UI + scanner binaries), `worker` (Redis queue consumer), `postgres`, `redis`, `neo4j`.
Containers run as non-root, read-only, all capabilities dropped. Put a TLS reverse proxy in front of port 8000.

## Tests

```bash
cd backend && .venv/Scripts/python -m pytest -q          # 41 tests: rules, YAML/ZIP safety, API/RBAC/isolation, reports, agents, Redis worker
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
* Recommended token: fine-grained, read-only (Contents, Metadata, Actions, Administration, Environments). `Test` in Settings warns about classic write scopes.
* Prompts mark repository content as untrusted; AI output is schema-validated and cannot change control status.

## Known limitations

* Only GitHub Actions is assessed; other CI files are detected and reported as NOT ASSESSED.
* Organization-level controls (audit-log streaming, SSO) need manual validation; several repository settings need an admin-capable token.
* Absence-based controls (SBOM, signing, provenance) are indicators: signing done outside the workflow cannot be seen.
