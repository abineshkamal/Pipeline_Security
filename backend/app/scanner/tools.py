"""Controlled execution of external security scanners.

Safety properties:
* Binaries are resolved to absolute paths; commands are argument lists (never a shell).
* Each run has a timeout and a scrubbed environment (no PT_*/LLM/GitHub credentials are inherited).
* Tools only read the extracted workspace; no repository code is executed by PipelineTrust itself.
* Missing tools produce status "missing" -> dependent controls become NOT_ASSESSED (never PASS).
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Callable

from ..config import get_settings

DEFAULT_TOOLS = ["gitleaks", "actionlint", "zizmor", "trivy", "syft"]
OPTIONAL_TOOLS = ["trufflehog", "grype", "checkov", "kics"]
ALL_TOOLS = DEFAULT_TOOLS + OPTIONAL_TOOLS

SAFE_ENV_KEYS = {"PATH", "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "TEMP", "TMP", "HOME", "USERPROFILE", "APPDATA",
                 "LOCALAPPDATA", "PROGRAMDATA", "COMSPEC", "PATHEXT", "LANG", "LC_ALL", "TZ", "NUMBER_OF_PROCESSORS",
                 "PROCESSOR_ARCHITECTURE", "OS", "XDG_CACHE_HOME", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE",
                 "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy"}


def _search_dirs() -> list[str]:
    s = get_settings()
    dirs = []
    if s.tools_dir:
        dirs.extend(p for p in s.tools_dir.split(os.pathsep) if p)
    dirs.append(str(Path(sys.executable).parent))  # venv Scripts/bin (zizmor, checkov via pip)
    dirs.append(os.environ.get("PATH", ""))
    return dirs


def find_tool(name: str) -> str | None:
    return shutil.which(name, path=os.pathsep.join(_search_dirs()))


def _env(extra: dict | None = None) -> dict:
    env = {k: v for k, v in os.environ.items() if k in SAFE_ENV_KEYS or k.upper() in SAFE_ENV_KEYS}
    env["PATH"] = os.pathsep.join(_search_dirs())
    env.update(extra or {})
    return env


def _run(cmd: list[str], cwd: Path, timeout: int, env: dict | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=str(cwd), capture_output=True, timeout=timeout, env=_env(env), shell=False,
                          stdin=subprocess.DEVNULL, check=False)


def _cache_dir(tool: str) -> Path:
    d = get_settings().data_dir / "cache" / tool
    d.mkdir(parents=True, exist_ok=True)
    return d


def _rel(root: Path, p: str) -> str:
    """Normalize a tool-reported path to repo-relative POSIX form."""
    if not p:
        return ""
    s = p.replace("\\", "/")
    try:
        pp = Path(p)
        if pp.is_absolute():
            return pp.resolve().relative_to(root.resolve()).as_posix()
    except (ValueError, OSError):
        pass
    while s.startswith("./"):
        s = s[2:]
    return s.lstrip("/") if s.startswith("/") and not Path(s).exists() else s


def _snippet(root: Path, rel: str, line: int | None, redact_secret: str | None = None) -> str:
    if not line:
        return ""
    try:
        lines = (root / rel).read_text("utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    if not 0 < line <= len(lines):
        return ""
    text = lines[line - 1]
    if redact_secret and len(redact_secret) > 4:
        text = text.replace(redact_secret, redact_secret[:3] + "****REDACTED****")
    return f"{line:>4} | {text.strip()[:300]}"


# ------------------------------------------------------------------ individual tools

def run_gitleaks(root: Path, bin_: str, timeout: int) -> dict:
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "gl.json"
        p = _run([bin_, "dir", str(root), "--report-format", "json", "--report-path", str(out), "--no-banner",
                  "--exit-code", "0", "--redact", "--log-level", "error"], root, timeout)
        if not out.exists():
            return {"status": "error", "detail": (p.stderr or p.stdout).decode(errors="replace")[-500:]}
        data = json.loads(out.read_text("utf-8") or "[]")
    findings = []
    for f in data or []:
        rel = _rel(root, f.get("File", ""))
        findings.append({"rule": f.get("RuleID") or f.get("Description"), "file": rel, "line": f.get("StartLine"),
                         "snippet": _snippet(root, rel, f.get("StartLine"), f.get("Secret")) or f"(redacted match for {f.get('RuleID')})"})
    return {"status": "ok", "findings": findings}


def run_trufflehog(root: Path, bin_: str, timeout: int) -> dict:
    p = _run([bin_, "filesystem", str(root), "--json", "--no-update", "--no-verification", "--log-level=-1"], root, timeout)
    findings = []
    for line in p.stdout.decode(errors="replace").splitlines():
        try:
            f = json.loads(line)
        except json.JSONDecodeError:
            continue
        if "DetectorName" not in f:
            continue
        fs = ((f.get("SourceMetadata") or {}).get("Data") or {}).get("Filesystem") or {}
        rel = _rel(root, fs.get("file", ""))
        findings.append({"rule": f.get("DetectorName"), "file": rel, "line": fs.get("line"), "verified": bool(f.get("Verified")),
                         "snippet": _snippet(root, rel, fs.get("line"), f.get("Raw"))})
    if p.returncode not in (0, 183) and not findings:
        err = p.stderr.decode(errors="replace")[-500:]
        if err.strip():
            return {"status": "error", "detail": err}
    return {"status": "ok", "findings": findings}


def run_actionlint(root: Path, bin_: str, timeout: int, workflow_files: list[str]) -> dict:
    if not workflow_files:
        return {"status": "ok", "findings": []}
    p = _run([bin_, "-format", "{{json .}}", "-no-color", "-shellcheck=", "-pyflakes=", *workflow_files], root, timeout)
    raw = p.stdout.decode(errors="replace").strip()
    if p.returncode not in (0, 1) or (not raw and p.returncode == 1):
        return {"status": "error", "detail": p.stderr.decode(errors="replace")[-500:]}
    data = json.loads(raw or "[]")
    return {"status": "ok", "findings": [{"rule": d.get("kind"), "message": d.get("message"), "file": _rel(root, d.get("filepath", "")),
                                          "line": d.get("line"), "snippet": d.get("snippet", "")} for d in data or []]}


def run_zizmor(root: Path, bin_: str, timeout: int) -> dict:
    p = _run([bin_, "--format", "json", "--offline", "--no-progress", "--persona", "regular", str(root)], root, timeout,
             env={"NO_COLOR": "1"})
    raw = p.stdout.decode(errors="replace").strip()
    try:
        data = json.loads(raw or "[]")
    except json.JSONDecodeError:
        return {"status": "error", "detail": (p.stderr.decode(errors="replace") or raw)[-500:]}
    findings = []
    for f in data:
        det = f.get("determinations") or {}
        loc = next((l for l in f.get("locations", []) if (l.get("symbolic") or {}).get("kind") == "Primary"), None) or (f.get("locations") or [{}])[0]
        sym = loc.get("symbolic") or {}
        keyinfo = (sym.get("key") or {}).get("Local") or {}
        path = keyinfo.get("given_path") or keyinfo.get("verbatim_path") or keyinfo.get("path") or ""
        conc = (loc.get("concrete") or {}).get("location") or {}
        row = (conc.get("start_point") or {}).get("row")
        feature = (loc.get("concrete") or {}).get("feature", "")
        findings.append({"rule": f.get("ident"), "message": f"{f.get('desc')}" + (f" - {sym.get('annotation')}" if sym.get("annotation") else ""),
                         "file": _rel(root, path), "line": (row + 1) if isinstance(row, int) else None,
                         "severity": str(det.get("severity", "unknown")).lower(), "confidence": str(det.get("confidence", "")).lower(),
                         "snippet": feature[:400]})
    return {"status": "ok", "findings": findings}


def run_trivy(root: Path, bin_: str, timeout: int) -> dict:
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "trivy.json"
        p = _run([bin_, "fs", "--scanners", "vuln,misconfig", "--format", "json", "--output", str(out), "--quiet",
                  "--cache-dir", str(_cache_dir("trivy")), "--skip-version-check", "--timeout", f"{timeout}s", str(root)], root, timeout + 30)
        if not out.exists() or out.stat().st_size == 0:
            return {"status": "error", "detail": (p.stderr or p.stdout).decode(errors="replace")[-600:]}
        data = json.loads(out.read_text("utf-8"))
    vulns, mis = [], []
    for res in data.get("Results") or []:
        target = res.get("Target", "")
        for v in res.get("Vulnerabilities") or []:
            vulns.append({"id": v.get("VulnerabilityID"), "package": v.get("PkgName"), "installed": v.get("InstalledVersion"),
                          "fixed": v.get("FixedVersion"), "severity": str(v.get("Severity", "unknown")).lower(),
                          "title": (v.get("Title") or "")[:200], "target": target})
        for m in res.get("Misconfigurations") or []:
            if m.get("Status") != "FAIL":
                continue
            sev = str(m.get("Severity", "low")).lower()
            mis.append({"id": m.get("AVDID") or m.get("ID"), "title": m.get("Title"), "severity": sev if sev in ("critical", "high", "medium", "low") else "low",
                        "file": target, "line": (m.get("CauseMetadata") or {}).get("StartLine"),
                        "message": f"{m.get('Message', '')}\nResolution: {m.get('Resolution', '')}"})
    return {"status": "ok", "vulnerabilities": vulns, "misconfigurations": mis}


def run_syft(root: Path, bin_: str, timeout: int, sbom_path: Path) -> dict:
    # `dir:.` with cwd=root: an absolute Windows path (dir:E:\...) is mis-parsed by syft's scheme detection.
    p = _run([bin_, "dir:.", "-o", f"cyclonedx-json={sbom_path.resolve()}", "-q"], root, timeout,
             env={"SYFT_CHECK_FOR_APP_UPDATE": "false"})
    if not sbom_path.exists():
        return {"status": "error", "detail": p.stderr.decode(errors="replace")[-500:]}
    try:
        comps = len(json.loads(sbom_path.read_text("utf-8")).get("components") or [])
    except (json.JSONDecodeError, OSError):
        comps = 0
    return {"status": "ok", "sbom_path": str(sbom_path), "components": comps}


def run_grype(root: Path, bin_: str, timeout: int, sbom_path: Path | None) -> dict:
    target = f"sbom:{sbom_path}" if sbom_path and sbom_path.exists() else f"dir:{root}"
    p = _run([bin_, target, "-o", "json", "-q"], root, timeout,
             env={"GRYPE_DB_CACHE_DIR": str(_cache_dir("grype")), "GRYPE_CHECK_FOR_APP_UPDATE": "false"})
    try:
        data = json.loads(p.stdout.decode(errors="replace") or "{}")
    except json.JSONDecodeError:
        return {"status": "error", "detail": p.stderr.decode(errors="replace")[-500:]}
    vulns = []
    for m in data.get("matches") or []:
        v, a = m.get("vulnerability") or {}, m.get("artifact") or {}
        locs = a.get("locations") or [{}]
        vulns.append({"id": v.get("id"), "package": a.get("name"), "installed": a.get("version"),
                      "fixed": ", ".join((v.get("fix") or {}).get("versions") or []), "severity": str(v.get("severity", "unknown")).lower(),
                      "target": _rel(root, (locs[0] or {}).get("path", "")).lstrip("/")})
    return {"status": "ok", "vulnerabilities": vulns}


def run_checkov(root: Path, bin_: str, timeout: int) -> dict:
    p = _run([bin_, "-d", str(root), "-o", "json", "--quiet", "--compact", "--skip-download", "--framework",
              "github_actions,dockerfile,terraform,kubernetes,secrets"], root, timeout)
    try:
        data = json.loads(p.stdout.decode(errors="replace") or "[]")
    except json.JSONDecodeError:
        return {"status": "error", "detail": p.stderr.decode(errors="replace")[-500:]}
    reports = data if isinstance(data, list) else [data]
    mis = []
    for rep in reports:
        for c in ((rep or {}).get("results") or {}).get("failed_checks") or []:
            rng = c.get("file_line_range") or [None]
            mis.append({"id": c.get("check_id"), "title": c.get("check_name"), "severity": str(c.get("severity") or "medium").lower(),
                        "file": str(c.get("file_path", "")).lstrip("/"), "line": rng[0], "message": c.get("guideline") or ""})
    return {"status": "ok", "misconfigurations": mis}


def run_kics(root: Path, bin_: str, timeout: int) -> dict:
    with tempfile.TemporaryDirectory() as td:
        _run([bin_, "scan", "-p", str(root), "-o", td, "--report-formats", "json", "--no-progress", "--disable-secrets"], root, timeout)
        f = Path(td) / "results.json"
        if not f.exists():
            return {"status": "error", "detail": "kics produced no results.json"}
        data = json.loads(f.read_text("utf-8"))
    mis = []
    for q in data.get("queries") or []:
        for fl in q.get("files") or []:
            mis.append({"id": q.get("query_id"), "title": q.get("query_name"), "severity": str(q.get("severity", "low")).lower(),
                        "file": _rel(root, fl.get("file_name", "")), "line": fl.get("line"),
                        "message": f"expected: {fl.get('expected_value')} / actual: {fl.get('actual_value')}"})
    return {"status": "ok", "misconfigurations": mis}


# ------------------------------------------------------------------ orchestration

def tool_inventory() -> list[dict]:
    return [{"name": t, "path": find_tool(t), "available": bool(find_tool(t)), "default": t in DEFAULT_TOOLS} for t in ALL_TOOLS]


def run_tools(root: Path, selected: list[str], workflow_files: list[str], artifacts_dir: Path,
              progress: Callable[[str], None] | None = None) -> tuple[dict, list[dict]]:
    """Run selected tools; returns (results by tool, run log). Never raises for tool failures."""
    timeout = get_settings().tool_timeout_seconds
    results: dict = {}
    log: list[dict] = []
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    sbom_path = artifacts_dir / "sbom.cdx.json"
    order = [t for t in ALL_TOOLS if t in selected]
    if "grype" in order and "syft" in order:  # grype reuses syft's SBOM
        order.remove("grype")
        order.append("grype")
    for name in order:
        bin_ = find_tool(name)
        started = time.time()
        if not bin_:
            results[name] = {"status": "missing", "detail": f"{name} binary not found on PATH / PT_TOOLS_DIR"}
        else:
            if progress:
                progress(f"Running {name}")
            try:
                if name == "gitleaks":
                    results[name] = run_gitleaks(root, bin_, timeout)
                elif name == "trufflehog":
                    results[name] = run_trufflehog(root, bin_, timeout)
                elif name == "actionlint":
                    results[name] = run_actionlint(root, bin_, timeout, workflow_files)
                elif name == "zizmor":
                    results[name] = run_zizmor(root, bin_, timeout)
                elif name == "trivy":
                    results[name] = run_trivy(root, bin_, timeout)
                elif name == "syft":
                    results[name] = run_syft(root, bin_, timeout, sbom_path)
                elif name == "grype":
                    results[name] = run_grype(root, bin_, timeout, sbom_path)
                elif name == "checkov":
                    results[name] = run_checkov(root, bin_, timeout)
                elif name == "kics":
                    results[name] = run_kics(root, bin_, timeout)
            except subprocess.TimeoutExpired:
                results[name] = {"status": "timeout", "detail": f"exceeded {timeout}s"}
            except Exception as exc:  # noqa: BLE001 - tool failures must not abort the scan
                results[name] = {"status": "error", "detail": f"{type(exc).__name__}: {exc}"[:500]}
        r = results[name]
        log.append({"tool": name, "status": r.get("status"), "detail": r.get("detail", ""), "seconds": round(time.time() - started, 1),
                    "count": len(r.get("findings", [])) + len(r.get("vulnerabilities", [])) + len(r.get("misconfigurations", []))
                    if r.get("status") == "ok" else 0})
    for name in ALL_TOOLS:
        if name not in selected:
            log.append({"tool": name, "status": "skipped", "detail": "not selected for this scan", "seconds": 0, "count": 0})
    return results, log
