"""Environment-based configuration. Every setting can be overridden with a PT_* env var."""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="PT_", env_file=BASE_DIR / ".env", extra="ignore")

    env: str = "development"
    # SQLite locally; postgresql+psycopg://user:pw@host/db in production.
    database_url: str = ""
    # JWT signing secret and the key used to encrypt stored credentials (Fernet urlsafe-base64 32-byte key).
    jwt_secret: str = "dev-only-change-me-jwt-secret-0123456789abcdef"
    jwt_ttl_minutes: int = 480
    encryption_key: str = ""  # derived from jwt_secret in dev if empty; REQUIRED in production
    data_dir: Path = BASE_DIR / "data"
    tools_dir: str = ""  # extra directory searched for scanner binaries
    cors_origins: list[str] = Field(default_factory=lambda: ["http://localhost:3000"])
    frontend_dir: str = ""  # if set, the static Next.js export is served from /

    # Upload / workspace safety limits
    max_upload_mb: int = 100
    max_extracted_mb: int = 500
    max_extracted_files: int = 50_000
    tool_timeout_seconds: int = 300

    # Background jobs: empty = in-process thread pool; redis://... = Redis queue + separate worker process
    redis_url: str = ""

    # Optional Neo4j mirror of the attack graph
    neo4j_uri: str = ""
    neo4j_user: str = "neo4j"
    neo4j_password: str = ""

    # AI / LLM. provider: none | anthropic | openai | fake (tests)
    llm_provider: str = "none"
    llm_model: str = ""
    anthropic_api_key: str = ""
    openai_api_key: str = ""
    llm_timeout_seconds: int = 120

    github_api_url: str = "https://api.github.com"

    # Continuous monitoring
    scheduler_enabled: bool = True  # scheduled scans + exception expiry; run it on one instance only
    scheduler_interval_seconds: int = 60
    public_url: str = ""  # e.g. https://pipelinetrust.example.com - used for links in alerts
    allow_private_webhooks: bool = False  # allow alert webhooks to private/loopback addresses (lab use only)
    auto_migrate: bool = True  # run Alembic on startup (disable when the container entrypoint migrates)

    @property
    def is_production(self) -> bool:
        return self.env.lower() == "production"

    @property
    def db_url(self) -> str:
        return normalize_db_url(self.database_url) or f"sqlite:///{(self.data_dir / 'pipelinetrust.db').as_posix()}"


def normalize_db_url(url: str) -> str:
    """Accept provider-style URLs (Railway/Heroku `postgres://` / `postgresql://`) and select the psycopg 3 driver."""
    url = (url or "").strip()
    for prefix in ("postgres://", "postgresql://"):
        if url.startswith(prefix):
            return "postgresql+psycopg://" + url[len(prefix):]
    return url


@lru_cache
def get_settings() -> Settings:
    s = Settings()
    s.data_dir.mkdir(parents=True, exist_ok=True)
    if s.is_production and (s.jwt_secret.startswith("dev-only") or not s.encryption_key):
        raise RuntimeError("PT_JWT_SECRET and PT_ENCRYPTION_KEY must be set in production")
    return s
