"""CICD-SEC-3: Dependency Chain Abuse."""
from __future__ import annotations

import re

from ..model import Rule, RuleOutcome, Status, Workflow, WorkflowRule
from ._util import iter_run_matches, tools_outcome

DEP_CONFUSION = "https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-03-Dependency-Chain-Abuse"

UNTRUSTED_SOURCE_PATTERNS: list[tuple[str, str, str]] = [
    (r"(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(ba|z|da)?sh\b", "remote script piped to a shell", "high"),
    (r"(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?python[0-9.]*\b", "remote script piped to python", "high"),
    (r"--extra-index-url\s+\S+", "pip --extra-index-url (dependency confusion risk)", "medium"),
    (r"--(index-url|registry|repository-url|source)\s*[= ]\s*['\"]?http://\S+", "package index over plain HTTP", "high"),
    (r"--trusted-host\s+\S+", "pip --trusted-host disables TLS verification", "medium"),
    (r"npm\s+config\s+set\s+strict-ssl\s+false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0|GIT_SSL_NO_VERIFY\s*=\s*['\"]?(1|true)|sslVerify\s*=?\s*false|--insecure\b|\s-k\s+https?://", "TLS verification disabled", "medium"),
    (r"pip3?\s+install\s+[^\n]*git\+http://", "pip install from plain-HTTP git URL", "high"),
    (r"(npm|yarn|pnpm)\s+(install|add)\s+[^\n]*https?://[^\s]+\.(tgz|tar\.gz)", "package installed from arbitrary tarball URL", "medium"),
]
_UNTRUSTED = [(re.compile(p, re.I), d, s) for p, d, s in UNTRUSTED_SOURCE_PATTERNS]

PIP_TOOLING = {"pip", "setuptools", "wheel", "pip-tools", "build", "twine", "virtualenv", "pipx", "uv", "poetry"}


def nondeterministic_installs(script: str) -> list[tuple[str, str]]:
    """Return (command_text, description) for installs that bypass lockfiles/pins."""
    hits = []
    for raw in script.splitlines():
        line = raw.strip()
        for cmd in re.split(r"&&|;|\|\|", line):
            toks = cmd.split()
            if len(toks) < 2:
                if toks[:1] == ["yarn"]:
                    hits.append((cmd.strip(), "`yarn` install without --frozen-lockfile/--immutable"))
                continue
            t0, t1 = toks[0].lower(), toks[1].lower()
            rest = set(toks[2:])
            if t0 == "npm" and t1 in ("install", "i") and not ({"-g", "--global"} & rest) and all(t.startswith("-") for t in toks[2:]):
                hits.append((cmd.strip(), "`npm install` (use `npm ci` for lockfile-exact installs)"))
            elif t0 == "yarn" and t1 == "install" and not ({"--frozen-lockfile", "--immutable"} & rest):
                hits.append((cmd.strip(), "`yarn install` without --frozen-lockfile/--immutable"))
            elif t0 == "pnpm" and t1 == "install" and "--frozen-lockfile" not in rest:
                hits.append((cmd.strip(), "`pnpm install` without --frozen-lockfile"))
            elif t0 in ("pip", "pip3") or (t0.startswith("python") and t1 == "-m" and len(toks) > 3 and toks[2] == "pip"):
                args = toks[2:] if t0.startswith("pip") else toks[4:]
                if (toks[1] if t0.startswith("pip") else toks[3]) != "install":
                    continue
                if "--require-hashes" in args:
                    continue
                skip_next = False
                for a in args:
                    if skip_next:
                        skip_next = False
                        continue
                    if a in ("-r", "--requirement", "-c", "--constraint", "-e", "--editable", "-i", "--index-url", "--extra-index-url", "-f", "--find-links", "--target", "-t"):
                        skip_next = True
                        continue
                    if a.startswith("-") or a.startswith(".") or a.startswith("/") or "://" in a or a.startswith("$"):
                        continue
                    pkg = re.split(r"[\[<>=!~]", a.strip("'\""), maxsplit=1)[0].lower()
                    if pkg in PIP_TOOLING:
                        continue
                    if "==" not in a:
                        hits.append((cmd.strip(), f"`pip install {a}` without a pinned version"))
                        break
            elif t0 == "go" and t1 in ("install", "get") and any(t.endswith("@latest") for t in toks[2:]):
                hits.append((cmd.strip(), "Go module fetched @latest"))
    return hits

MANIFEST_LOCKS = {
    "package.json": ["package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb", "bun.lock"],
    "pyproject.toml": ["poetry.lock", "uv.lock", "pdm.lock", "Pipfile.lock", "requirements.txt"],
    "Pipfile": ["Pipfile.lock"],
    "Gemfile": ["Gemfile.lock"],
    "Cargo.toml": ["Cargo.lock"],
    "go.mod": ["go.sum"],
    "composer.json": ["composer.lock"],
}


class UntrustedDependencySource(WorkflowRule):
    id = "PT-DEP-001"
    category = "CICD-SEC-3"
    title = "Untrusted or insecure dependency source in pipeline"
    description = ("The pipeline fetches code from sources that can be hijacked: remote scripts piped to a shell, "
                   "plain-HTTP indexes, extra package indexes (dependency confusion), or TLS verification turned off.")
    severity = "high"
    cwe = ["CWE-494", "CWE-829", "CWE-295"]
    references = [DEP_CONFUSION]
    remediation = ("Download installers to a file, verify a pinned checksum/signature, then execute. Use a single "
                   "trusted (proxy) registry with HTTPS; use `--index-url` with scoped/namespaced private packages instead of `--extra-index-url`.")
    evidence_requirements = "Exact command line in a `run:` step."
    false_positives = "Vendor installers fetched over HTTPS from the vendor's own domain are lower risk but still unverified."

    def check(self, ctx, wf: Workflow):
        out = []
        for rx, desc, sev in _UNTRUSTED:
            for job, step, m, line in iter_run_matches(wf, rx):
                out.append(self.finding(f"{desc.capitalize()} in job `{job.id}`: `{m.group(0).strip()[:120]}`",
                                        wf=wf, job=job, line=line, severity=sev, key=f"{job.id}:{step.index}:{desc}"))
        for job in wf.jobs:
            for step in job.steps:
                env = wf.env_at(job, step)
                for k, v in env.items():
                    if k in ("NODE_TLS_REJECT_UNAUTHORIZED",) and str(v) == "0" or k == "GIT_SSL_NO_VERIFY" and str(v).lower() in ("1", "true"):
                        out.append(self.finding(f"`{k}={v}` disables TLS verification in job `{job.id}`.", wf=wf, job=job,
                                                line=wf.find_line(k, start=job.line) or job.line, severity="medium", key=f"{job.id}:{k}"))
                        break
        # de-duplicate env findings that repeat per step
        seen, uniq = set(), []
        for f in out:
            if f.fingerprint not in seen:
                seen.add(f.fingerprint)
                uniq.append(f)
        return uniq


class NonDeterministicInstall(WorkflowRule):
    id = "PT-DEP-002"
    category = "CICD-SEC-3"
    title = "Dependencies installed without lockfile enforcement"
    description = "Install commands resolve versions at build time instead of from a lockfile, so a malicious new release is pulled in automatically."
    severity = "low"
    cwe = ["CWE-1357", "CWE-494"]
    references = [DEP_CONFUSION]
    remediation = "Use `npm ci`, `yarn install --immutable`, `pnpm install --frozen-lockfile`, `pip install --require-hashes -r requirements.txt`, and pinned tool versions."
    evidence_requirements = "Exact install command in a `run:` step."
    false_positives = "Installing build tooling (e.g. `pip install --upgrade pip`) is excluded; global tooling installs may be acceptable."

    def check(self, ctx, wf: Workflow):
        out = []
        for job in wf.jobs:
            for step in job.steps:
                if not step.run:
                    continue
                for cmd, desc in nondeterministic_installs(step.run):
                    line = wf.find_line(cmd[:60], start=step.key_line("run")) or step.key_line("run")
                    out.append(self.finding(f"{desc} in job `{job.id}`.", wf=wf, job=job, line=line, confidence="medium",
                                            key=f"{job.id}:{step.index}:{cmd}"))
        return out


class MissingLockfiles(Rule):
    id = "PT-DEP-003"
    category = "CICD-SEC-3"
    title = "Dependency manifests without lockfiles"
    description = "Package manifests exist without a corresponding lockfile, so builds are not reproducible and transitive versions float."
    severity = "low"
    cwe = ["CWE-1357"]
    references = [DEP_CONFUSION]
    remediation = "Commit lockfiles for every manifest and enforce them in CI."
    evidence_requirements = "Presence of a manifest and absence of any lockfile in the same directory."
    false_positives = "Libraries sometimes intentionally omit lockfiles; applications should not."
    data_sources = ["repo_files"]

    def evaluate(self, ctx):
        files = set(ctx.files)
        manifests = [f for f in ctx.files if f.rsplit("/", 1)[-1] in MANIFEST_LOCKS and "node_modules/" not in f and "/vendor/" not in f]
        if not manifests:
            return RuleOutcome(Status.NOT_APPLICABLE, note="No supported dependency manifests found.")
        out = []
        for m in manifests:
            d = m.rsplit("/", 1)[0] + "/" if "/" in m else ""
            name = m.rsplit("/", 1)[-1]
            locks = MANIFEST_LOCKS[name]
            if name == "pyproject.toml":
                txt = ctx.read_text(m) or ""
                if "[project]" not in txt and "[tool.poetry]" not in txt:
                    continue
            if not any(d + lk in files for lk in locks):
                out.append(self.finding(f"`{m}` has no lockfile ({' / '.join(locks[:3])}).", file_path=m, line=1, key=m,
                                        snippet="(lockfile absent)"))
        return self.outcome_from(out, pass_evidence=f"{len(manifests)} manifest(s) have lockfiles.")


class VulnerableDependencies(Rule):
    id = "PT-DEP-004"
    category = "CICD-SEC-3"
    title = "Known-vulnerable dependencies"
    description = "Software composition analysis (Trivy / Grype) found dependencies with published vulnerabilities."
    severity = "high"
    cwe = ["CWE-1395", "CWE-937"]
    references = ["https://owasp.org/www-project-dependency-check/"]
    remediation = "Upgrade the affected packages to the fixed versions listed; add automated dependency updates and a dependency-review gate."
    evidence_requirements = "Tool output: package, installed version, CVE, fixed version, manifest path."
    false_positives = "Vulnerable code paths may be unreachable; development-only dependencies have lower impact."
    data_sources = ["tool:trivy", "tool:grype"]

    def evaluate(self, ctx):
        ok, bad = tools_outcome(ctx, ["trivy", "grype"])
        if bad:
            return bad
        by_target: dict[str, dict] = {}
        for tool, r in ok:
            for v in r.get("vulnerabilities", []):
                t = by_target.setdefault(v.get("target") or "(unknown)", {"items": {}, "tools": set()})
                t["items"][(v.get("id"), v.get("package"))] = v
                t["tools"].add(tool)
        out = []
        sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        for target, info in by_target.items():
            vulns = sorted(info["items"].values(), key=lambda x: -sev_rank.get(x.get("severity", "low"), 0))
            top = vulns[0].get("severity", "low")
            counts: dict[str, int] = {}
            for v in vulns:
                counts[v.get("severity", "unknown")] = counts.get(v.get("severity", "unknown"), 0) + 1
            lines = [f"{v.get('id')}  {v.get('package')} {v.get('installed')} -> {v.get('fixed') or 'no fix'}  [{v.get('severity')}]" for v in vulns[:15]]
            out.append(self.finding(
                f"{len(vulns)} vulnerable package version(s) in `{target}` ({', '.join(f'{k}: {n}' for k, n in counts.items())}).",
                file_path=target, severity=top if top in sev_rank else "low", evidence_type="tool",
                snippet="\n".join(lines), key=target, tools=sorted(info["tools"]), vulnerabilities=vulns[:200],
            ))
        return self.outcome_from(out, pass_evidence=f"{', '.join(t for t, _ in ok)} reported no vulnerable dependencies.")
