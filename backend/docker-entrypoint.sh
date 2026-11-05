#!/bin/sh
# Container entrypoint (Railway, Docker Compose, plain docker run).
#  * Platforms like Railway mount volumes owned by root: when started as root we fix /data ownership,
#    then drop to the unprivileged `pt` user. When already non-root (Compose sets user: 10001) we skip that.
#  * Runs database migrations once, then starts the API on $PORT (Railway) or 8000.
set -eu

DATA_DIR="${PT_DATA_DIR:-/data}"

if [ "$(id -u)" = "0" ]; then
  mkdir -p "$DATA_DIR"
  chown -R pt:pt "$DATA_DIR" 2>/dev/null || echo "warning: could not chown $DATA_DIR"
  exec setpriv --reuid=pt --regid=pt --init-groups --inh-caps=-all "$0" "$@"
fi

if [ "$#" -gt 0 ]; then
  exec "$@"   # e.g. `python -m app.worker` for a worker service
fi

alembic upgrade head
export PT_AUTO_MIGRATE=false
exec uvicorn app.main:app --host 0.0.0.0 --port "${PORT:-8000}" --proxy-headers --forwarded-allow-ips='*' --workers "${WEB_CONCURRENCY:-1}"
