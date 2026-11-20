"""Forward audit events and drift alerts to a SIEM: Splunk HTTP Event Collector, Datadog logs, or a generic
webhook signed with HMAC-SHA256 (header X-PipelineTrust-Signature: sha256=<hex>).

Delivery runs on one background worker so requests never wait on the SIEM; failures are counted on the sink.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor

import httpx
from sqlalchemy import select

from ..db import SessionLocal
from ..models import SiemSink
from ..security import decrypt_secret
from .monitoring import UnsafeURL, validate_webhook_url

log = logging.getLogger("pipelinetrust.siem")
_pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="pt-siem")
KINDS = ("splunk", "datadog", "webhook")


def build(kind: str, event_type: str, event: dict, secret: str) -> tuple[dict, bytes]:
    doc = {"source": "pipelinetrust", "type": event_type, "time": time.time(), "event": event}
    if kind == "splunk":
        body = {"event": doc, "sourcetype": f"pipelinetrust:{event_type}", "source": "pipelinetrust", "time": doc["time"]}
        return {"Authorization": f"Splunk {secret}"}, json.dumps(body).encode()
    if kind == "datadog":
        body = [{"ddsource": "pipelinetrust", "service": "pipelinetrust", "ddtags": f"type:{event_type}", "message": json.dumps(doc)}]
        return {"DD-API-KEY": secret}, json.dumps(body).encode()
    raw = json.dumps(doc).encode()
    headers = {"X-PipelineTrust-Event": event_type}
    if secret:
        headers["X-PipelineTrust-Signature"] = "sha256=" + hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()
    return headers, raw


def post(url: str, headers: dict, body: bytes) -> int:
    with httpx.Client(timeout=10, follow_redirects=False) as c:
        return c.post(url, content=body, headers={"Content-Type": "application/json", "User-Agent": "PipelineTrust-SIEM", **headers}).status_code


def deliver(sink: SiemSink, event_type: str, event: dict) -> tuple[bool, str]:
    try:
        url = validate_webhook_url(decrypt_secret(sink.url_encrypted))
        headers, body = build(sink.kind, event_type, event, decrypt_secret(sink.secret_encrypted) if sink.secret_encrypted else "")
        code = post(url, headers, body)
        return 200 <= code < 300, f"HTTP {code}"
    except (UnsafeURL, httpx.HTTPError, ValueError) as exc:
        return False, f"{type(exc).__name__}: {exc}"[:300]


def _dispatch(org_id: str, event_type: str, event: dict) -> None:
    with SessionLocal() as db:
        sinks = db.execute(select(SiemSink).where(SiemSink.organization_id == org_id, SiemSink.enabled.is_(True))).scalars().all()
        for s in sinks:
            if s.events and event_type not in s.events:
                continue
            ok, detail = deliver(s, event_type, event)
            if ok:
                s.delivered += 1
            else:
                s.failed += 1
                s.last_error = detail
        if sinks:
            db.commit()


def emit(org_id: str | None, event_type: str, event: dict) -> None:
    if not org_id:
        return
    try:
        _pool.submit(_dispatch, org_id, event_type, event)
    except RuntimeError:  # interpreter shutting down
        pass


def flush(timeout: float = 10) -> None:
    """Wait until queued deliveries are done (tests, shutdown)."""
    _pool.submit(lambda: None).result(timeout=timeout)
