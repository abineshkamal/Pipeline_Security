"""Background job dispatch.

* PT_REDIS_URL unset  -> in-process ThreadPoolExecutor (development / single node).
* PT_REDIS_URL set    -> scan ids are pushed to a Redis list and executed by `python -m app.worker`.
"""
from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor

from ..config import get_settings

log = logging.getLogger("pipelinetrust.jobs")
QUEUE_KEY = "pipelinetrust:scans"
_pool: ThreadPoolExecutor | None = None


def _redis():
    import redis

    return redis.Redis.from_url(get_settings().redis_url)


def enqueue_scan(scan_id: str) -> str:
    if get_settings().redis_url:
        _redis().rpush(QUEUE_KEY, scan_id)
        return "redis"
    global _pool
    if _pool is None:
        _pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="pt-scan")
    from .scan_runner import execute_scan

    _pool.submit(execute_scan, scan_id)
    return "thread"


def worker_loop(client=None, once: bool = False, timeout: int = 5) -> int:
    """Consume scan ids from Redis. Returns number processed (used by tests with once=True)."""
    from .scan_runner import execute_scan

    r = client or _redis()
    done = 0
    while True:
        item = r.blpop([QUEUE_KEY], timeout=timeout)
        if item:
            sid = item[1].decode() if isinstance(item[1], bytes) else item[1]
            log.info("worker executing scan %s", sid)
            execute_scan(sid)
            done += 1
        if once:
            return done
