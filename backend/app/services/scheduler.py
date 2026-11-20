"""Scheduled scans and exception expiry.

A daemon thread wakes every `scheduler_interval_seconds`, queues a scan for each GitHub project whose schedule is
due, and reopens findings whose risk exception has expired. Claiming a due project is an atomic compare-and-set on
`next_scan_at`, so two instances never queue the same run; still, enable the scheduler on one instance only
(PT_SCHEDULER_ENABLED=false on workers).
"""
from __future__ import annotations

import logging
import threading
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, update

from ..config import get_settings
from ..db import SessionLocal
from ..models import Project, Scan
from ..scanner.tools import DEFAULT_TOOLS
from . import jobs
from .audit import record
from .exceptions import expire_due

log = logging.getLogger("pipelinetrust.scheduler")
INTERVALS = {"daily": timedelta(days=1), "weekly": timedelta(days=7)}
_thread: threading.Thread | None = None
_stop = threading.Event()


def now() -> datetime:
    return datetime.now(timezone.utc)


def next_run(schedule: str, start: datetime | None = None) -> datetime | None:
    return (start or now()) + INTERVALS[schedule] if schedule in INTERVALS else None


def _aware(d: datetime | None) -> datetime | None:
    return d.replace(tzinfo=timezone.utc) if d and d.tzinfo is None else d  # SQLite returns naive UTC


def run_due(at: datetime | None = None) -> list[str]:
    """Queue every due scheduled scan. Returns the queued scan ids."""
    at = at or now()
    queued: list[str] = []
    with SessionLocal() as db:
        due = db.execute(select(Project).where(Project.schedule.in_(list(INTERVALS)), Project.source_type == "github",
                                               Project.next_scan_at.is_not(None), Project.next_scan_at <= at)).scalars().all()
        for p in due:
            old = p.next_scan_at
            nxt = next_run(p.schedule, max(_aware(old), at - INTERVALS[p.schedule]))
            while nxt <= at:  # catch up after downtime without queuing a backlog
                nxt += INTERVALS[p.schedule]
            claimed = db.execute(update(Project).where(Project.id == p.id, Project.next_scan_at == old)
                                 .values(next_scan_at=nxt)).rowcount
            db.commit()
            if not claimed:
                continue
            busy = db.execute(select(Scan.id).where(Scan.project_id == p.id, Scan.status.in_(["queued", "running"])).limit(1)).first()
            if busy:
                continue
            s = Scan(organization_id=p.organization_id, project_id=p.id, created_by=None,
                     options={"tools": list(DEFAULT_TOOLS), "run_tools": True, "ai": True, "trigger": "schedule"})
            db.add(s)
            db.commit()
            jobs.enqueue_scan(s.id)
            record(db, p.organization_id, None, "scan.scheduled", f"scan:{s.id}", {"project": p.name, "schedule": p.schedule})
            queued.append(s.id)
        expire_due(db)
    return queued


def _loop(interval: int) -> None:
    while not _stop.wait(interval):
        try:
            ids = run_due()
            if ids:
                log.info("queued %d scheduled scan(s)", len(ids))
        except Exception as exc:  # noqa: BLE001 - keep the scheduler alive
            log.error("scheduler tick failed: %s", exc)


def start() -> None:
    global _thread
    s = get_settings()
    if not s.scheduler_enabled or (_thread and _thread.is_alive()):
        return
    _stop.clear()
    _thread = threading.Thread(target=_loop, args=(max(10, s.scheduler_interval_seconds),), name="pt-scheduler", daemon=True)
    _thread.start()
    log.info("scheduler started (every %ss)", s.scheduler_interval_seconds)


def stop() -> None:
    _stop.set()
