"""Redis-backed scan worker: `python -m app.worker` (requires PT_REDIS_URL)."""
import logging

from .config import get_settings
from .services.jobs import worker_loop

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    if not get_settings().redis_url:
        raise SystemExit("PT_REDIS_URL is not set")
    worker_loop()
