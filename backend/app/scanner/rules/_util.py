"""Shared helpers for rule modules (underscore modules are not scanned for rules)."""
from __future__ import annotations

import re
from collections.abc import Iterator

from ..model import Job, RuleOutcome, Status, Step, Workflow


def iter_run_matches(wf: Workflow, pattern: re.Pattern) -> Iterator[tuple[Job, Step, re.Match, int]]:
    """Yield (job, step, match, line) for each regex match inside `run:` scripts with exact line numbers."""
    for job in wf.jobs:
        for step in job.steps:
            if not step.run:
                continue
            start = step.key_line("run")
            for m in pattern.finditer(step.run):
                first_line = m.group(0).strip().splitlines()[0] if m.group(0).strip() else m.group(0)
                line = wf.find_line(first_line[:80], start=start) or start
                yield job, step, m, line


def tool_outcome(ctx, tool: str) -> tuple[dict | None, RuleOutcome | None]:
    """Return (result, None) if tool ran OK, else (None, NOT_ASSESSED outcome)."""
    r = ctx.tool_results.get(tool)
    if not r:
        return None, RuleOutcome(Status.NOT_ASSESSED, note=f"{tool} was not run in this scan.")
    if r.get("status") != "ok":
        return None, RuleOutcome(Status.NOT_ASSESSED, note=f"{tool}: {r.get('status')} - {r.get('detail', '')}".strip(" -"))
    return r, None


def tools_outcome(ctx, tools: list[str]) -> tuple[list[tuple[str, dict]], RuleOutcome | None]:
    ok = []
    notes = []
    for t in tools:
        r, bad = tool_outcome(ctx, t)
        if r:
            ok.append((t, r))
        else:
            notes.append(bad.note)
    if not ok:
        return [], RuleOutcome(Status.NOT_ASSESSED, note=" ".join(notes))
    return ok, None
