from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from sqlalchemy import update

from .api import auth, projects, scans
from .config import BASE_DIR, get_settings
from .db import SessionLocal
from .models import Scan, utcnow

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("pipelinetrust")


def run_migrations() -> None:
    from alembic import command
    from alembic.config import Config

    cfg = Config(str(BASE_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(BASE_DIR / "alembic"))
    cfg.set_main_option("sqlalchemy.url", get_settings().db_url)
    command.upgrade(cfg, "head")


def recover_interrupted() -> None:
    """In thread mode, scans that were running when the process stopped can never finish - mark them failed."""
    if get_settings().redis_url:
        return
    with SessionLocal() as db:
        n = db.execute(update(Scan).where(Scan.status.in_(["queued", "running"]))
                       .values(status="failed", error="interrupted by server restart", progress="Failed", finished_at=utcnow())).rowcount
        db.commit()
        if n:
            log.warning("marked %d interrupted scan(s) as failed", n)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    if get_settings().auto_migrate:
        run_migrations()
    recover_interrupted()
    yield


s = get_settings()
app = FastAPI(title="PipelineTrust API", version="1.0.0", description="AI-Powered CI/CD Security Assurance (OWASP Top 10 CI/CD)",
              lifespan=lifespan, docs_url="/api/docs", openapi_url="/api/openapi.json", redoc_url=None)
app.add_middleware(CORSMiddleware, allow_origins=s.cors_origins, allow_credentials=False,
                   allow_methods=["GET", "POST", "PATCH", "DELETE"], allow_headers=["Authorization", "Content-Type", "X-Org-Id"])


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    resp.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    if request.url.path.startswith("/api/scans/") and request.url.path.endswith("report.html"):
        resp.headers["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'"
    elif not request.url.path.startswith("/api/docs"):
        resp.headers.setdefault("Content-Security-Policy",
                                "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
                                "connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
    if s.is_production:
        resp.headers.setdefault("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
    return resp


@app.exception_handler(Exception)
async def unhandled(_request: Request, exc: Exception):
    log.exception("unhandled error: %s", exc)
    return JSONResponse({"detail": "internal server error"}, status_code=500)


app.include_router(auth.router)
app.include_router(projects.router)
app.include_router(scans.router)


@app.get("/api/health")
def health():
    from .agents.llm import get_provider
    from .scanner.tools import tool_inventory

    p = get_provider()
    return {"status": "ok", "llm": {"provider": p.name, "model": p.model, "available": p.available},
            "queue": "redis" if s.redis_url else "thread", "neo4j": bool(s.neo4j_uri),
            "tools": {t["name"]: t["available"] for t in tool_inventory()}}


# Serve the static Next.js export (single-origin deployment) when configured.
if s.frontend_dir and Path(s.frontend_dir).is_dir():
    root = Path(s.frontend_dir).resolve()

    @app.get("/{path:path}", include_in_schema=False)
    def spa(path: str):
        if path.startswith("api/"):
            return JSONResponse({"detail": "not found"}, status_code=404)
        for cand in (root / path, root / f"{path}.html", root / path / "index.html"):
            try:
                c = cand.resolve()
            except OSError:
                continue
            if c.is_file() and c.is_relative_to(root):
                return FileResponse(c)
        return FileResponse(root / "index.html")
