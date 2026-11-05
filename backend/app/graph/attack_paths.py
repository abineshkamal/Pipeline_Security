"""Attack-path analysis.

Builds a directed graph  actor -> trigger -> job -> capability -> impact  where *every* actor->job edge is backed
by a deterministic finding (code-execution evidence). Paths are enumerated with networkx; nothing is inferred by
an LLM. The graph is stored as JSON on the scan and can optionally be mirrored to Neo4j.
"""
from __future__ import annotations

import logging

import networkx as nx

from ..scanner.gha import (
    PRIVILEGED_EXTERNAL_TRIGGERS, effective_job_permissions, external_triggers, is_self_hosted, job_deploy_indicators,
    job_secret_names, write_scopes,
)
from ..scanner.model import FindingResult, ScanContext

log = logging.getLogger("pipelinetrust.graph")

ACTORS = {
    "actor:external": "External attacker (fork PR / issue / comment author)",
    "actor:insider": "Contributor with branch push access",
    "actor:supply": "Compromised third-party action maintainer",
}
IMPACTS = {
    "impact:secrets": ("Secret exfiltration", 0.9),
    "impact:repo": ("Repository tampering (backdoor commit / release)", 1.0),
    "impact:registry": ("Package / container registry poisoning", 1.0),
    "impact:cloud": ("Cloud account access via OIDC", 1.0),
    "impact:runner": ("Persistent runner compromise / internal network pivot", 0.9),
    "impact:deploy": ("Attacker code deployed to production", 1.0),
    "impact:workflows": ("Workflow / CI configuration modification", 0.8),
}
EXEC_RULES = {"PT-PPE-001", "PT-PPE-003", "PT-PPE-004", "PT-PPE-005"}
SUPPLY_RULES = {"PT-3P-001", "PT-3P-004"}


def _actor_for(f: FindingResult, wf) -> str | None:
    if f.rule_id in SUPPLY_RULES:
        if f.rule_id == "PT-3P-001" and (f.extra.get("first_party") or f.severity in ("low", "info")):
            return None
        return "actor:supply"
    if f.rule_id == "PT-PPE-005":
        return "actor:insider"
    if f.rule_id in EXEC_RULES:
        return "actor:external" if external_triggers(wf) else "actor:insider"
    return None


def build_attack_graph(ctx: ScanContext, findings: list[FindingResult], max_paths: int = 40) -> dict:
    g = nx.DiGraph()
    wf_by_path = {w.path: w for w in ctx.parsed_workflows}
    public = ctx.metadata.is_public

    def node(nid: str, ntype: str, label: str, **data):
        if nid not in g:
            g.add_node(nid, type=ntype, label=label, **data)

    def edge(a: str, b: str, label: str, risk: float = 0.0, finding: str | None = None, gated: str = ""):
        if g.has_edge(a, b):
            e = g.edges[a, b]
            if finding and finding not in e["findings"]:
                e["findings"].append(finding)
            e["risk"] = max(e["risk"], risk)
            return
        g.add_edge(a, b, label=label, risk=risk, findings=[finding] if finding else [], gated=gated)

    for f in findings:
        wf = wf_by_path.get(f.file_path)
        if not wf or not f.job:
            continue
        actor = _actor_for(f, wf)
        if not actor:
            continue
        job = next((j for j in wf.jobs if j.id == f.job), None)
        if not job:
            continue
        node(actor, "actor", ACTORS[actor])
        jid = f"job:{wf.path}#{job.id}"
        node(jid, "job", f"{wf.name} / {job.id}", workflow=wf.path, job=job.id)
        gate = job.environment or ""
        if actor == "actor:supply":
            edge(actor, jid, f"runs mutable action {f.extra.get('action', '')}@{f.extra.get('ref', '')}".strip("@"), f.risk_score, f.fingerprint)
        else:
            trig = sorted(set(wf.triggers) & (PRIVILEGED_EXTERNAL_TRIGGERS | {"pull_request", "push", "workflow_dispatch", "pull_request_review", "pull_request_review_comment"})) or sorted(wf.triggers)
            tid = f"trigger:{wf.path}"
            node(tid, "trigger", f"{', '.join(trig)} -> {wf.name}", workflow=wf.path)
            edge(actor, tid, "triggers" if actor == "actor:external" else "pushes branch / triggers")
            edge(tid, jid, f.title, f.risk_score, f.fingerprint, gated=gate)

        # capabilities of the compromised job
        perms, src = effective_job_permissions(wf, job)
        writes = write_scopes(perms) if perms is not None else set()
        default_unknown = perms is None
        repo_default = ctx.metadata.get("workflow_permissions")
        default_write = default_unknown and (repo_default.status != "ok" or (repo_default.data or {}).get("default_workflow_permissions") == "write")
        for s in sorted(job_secret_names(job)):
            cid = f"secret:{s}"
            node(cid, "capability", f"secret {s}")
            edge(jid, cid, "reads", 0)
            node("impact:secrets", "impact", IMPACTS["impact:secrets"][0])
            edge(cid, "impact:secrets", "exfiltrate", 0)
        if "contents" in writes or default_write:
            cid = "cap:token-contents" if not default_write else "cap:token-default"
            node(cid, "capability", "GITHUB_TOKEN contents:write" if cid.endswith("contents") else "GITHUB_TOKEN (default perms, write unless restricted)")
            edge(jid, cid, "holds", 0)
            node("impact:repo", "impact", IMPACTS["impact:repo"][0])
            edge(cid, "impact:repo", "push code / tags", 0)
        if "packages" in writes:
            node("cap:token-packages", "capability", "GITHUB_TOKEN packages:write")
            edge(jid, "cap:token-packages", "holds", 0)
            node("impact:registry", "impact", IMPACTS["impact:registry"][0])
            edge("cap:token-packages", "impact:registry", "publish package", 0)
        if "id-token" in writes:
            node("cap:oidc", "capability", "OIDC id-token (cloud federation)")
            edge(jid, "cap:oidc", "requests", 0)
            node("impact:cloud", "impact", IMPACTS["impact:cloud"][0])
            edge("cap:oidc", "impact:cloud", "assume cloud role", 0)
        if "actions" in writes or "workflows" in writes:
            node("cap:token-actions", "capability", "GITHUB_TOKEN actions:write")
            edge(jid, "cap:token-actions", "holds", 0)
            node("impact:workflows", "impact", IMPACTS["impact:workflows"][0])
            edge("cap:token-actions", "impact:workflows", "modify runs/caches", 0)
        if is_self_hosted(job):
            rid = f"runner:{', '.join(job.runs_on)}"
            node(rid, "capability", f"self-hosted runner [{', '.join(job.runs_on)}]")
            edge(jid, rid, "executes on", 0)
            node("impact:runner", "impact", IMPACTS["impact:runner"][0])
            edge(rid, "impact:runner", "persist / pivot", 0)
        if job_deploy_indicators(job):
            did = f"deploy:{wf.path}#{job.id}"
            node(did, "capability", f"deployment step in {job.id}" + (f" (env {gate})" if gate else ""))
            edge(jid, did, "controls", 0, gated=gate)
            node("impact:deploy", "impact", IMPACTS["impact:deploy"][0])
            edge(did, "impact:deploy", "ship", 0)

    paths = []
    actors = [n for n, d in g.nodes(data=True) if d["type"] == "actor"]
    impacts = [n for n, d in g.nodes(data=True) if d["type"] == "impact"]
    for a in actors:
        for imp in impacts:
            try:
                for p in nx.all_simple_paths(g, a, imp, cutoff=6):
                    edges = [g.edges[p[i], p[i + 1]] for i in range(len(p) - 1)]
                    fps = sorted({fp for e in edges for fp in e["findings"]})
                    if not fps:
                        continue
                    gated = [e["gated"] for e in edges if e.get("gated")]
                    risk = max(e["risk"] for e in edges) * IMPACTS[imp][1]
                    if gated:
                        risk *= 0.6
                    if public and a == "actor:external":
                        risk = min(10.0, risk * 1.1)
                    paths.append({
                        "nodes": p, "labels": [g.nodes[n]["label"] for n in p], "impact": IMPACTS[imp][0],
                        "actor": ACTORS[a], "findings": fps, "risk": round(min(10.0, risk), 1),
                        "gated_by": sorted(set(gated)), "length": len(p) - 1,
                    })
            except nx.NetworkXNoPath:
                continue
    paths.sort(key=lambda x: (-x["risk"], x["length"]))
    # de-duplicate identical label chains
    seen, uniq = set(), []
    for p in paths:
        k = tuple(p["nodes"])
        if k not in seen:
            seen.add(k)
            p["id"] = f"AP-{len(uniq) + 1:02d}"
            uniq.append(p)
        if len(uniq) >= max_paths:
            break
    on_path = {n for p in uniq for n in p["nodes"]}
    return {
        "nodes": [{"id": n, **d, "on_path": n in on_path} for n, d in g.nodes(data=True)],
        "edges": [{"source": a, "target": b, **d} for a, b, d in g.edges(data=True)],
        "paths": uniq,
        "stats": {"nodes": g.number_of_nodes(), "edges": g.number_of_edges(), "paths": len(uniq)},
    }


def sync_to_neo4j(scan_id: str, graph: dict) -> str:
    """Mirror a scan's attack graph into Neo4j (optional; enabled when PT_NEO4J_URI is set)."""
    from ..config import get_settings

    s = get_settings()
    if not s.neo4j_uri:
        return "disabled"
    try:
        from neo4j import GraphDatabase
    except ImportError:
        return "neo4j driver not installed"
    driver = GraphDatabase.driver(s.neo4j_uri, auth=(s.neo4j_user, s.neo4j_password))
    try:
        with driver.session() as sess:
            sess.run("MATCH (n:PTNode {scan_id: $sid}) DETACH DELETE n", sid=scan_id)
            sess.run("UNWIND $nodes AS n MERGE (x:PTNode {scan_id: $sid, id: n.id}) SET x.type = n.type, x.label = n.label",
                     sid=scan_id, nodes=[{"id": n["id"], "type": n["type"], "label": n["label"]} for n in graph.get("nodes", [])])
            sess.run("UNWIND $edges AS e MATCH (a:PTNode {scan_id: $sid, id: e.source}), (b:PTNode {scan_id: $sid, id: e.target}) "
                     "MERGE (a)-[r:PT_EDGE {label: e.label}]->(b) SET r.risk = e.risk, r.findings = e.findings",
                     sid=scan_id, edges=[{"source": e["source"], "target": e["target"], "label": e["label"], "risk": e["risk"],
                                          "findings": e["findings"]} for e in graph.get("edges", [])])
        return "ok"
    except Exception as exc:  # noqa: BLE001
        log.warning("neo4j sync failed: %s", exc)
        return f"error: {exc}"
    finally:
        driver.close()
