import os
import sys
import tempfile
from pathlib import Path

_TMP = Path(tempfile.mkdtemp(prefix="pt-test-"))
os.environ["PT_DATA_DIR"] = str(_TMP)
os.environ["PT_DATABASE_URL"] = f"sqlite:///{(_TMP / 'test.db').as_posix()}"
os.environ["PT_LLM_PROVIDER"] = "none"
os.environ["PT_SCHEDULER_ENABLED"] = "false"  # tests call scheduler.run_due() directly
os.environ["PT_ALLOW_PRIVATE_WEBHOOKS"] = "true"  # no DNS lookups for example.com webhook hosts
os.environ.setdefault("PT_TOOLS_DIR", r"E:\tools\pt-bin")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

SAMPLES = Path(__file__).resolve().parents[2] / "samples"


@pytest.fixture(scope="session")
def client():
    from app import main
    from app.services import jobs

    # run scans synchronously inside the request for deterministic tests
    def _sync(scan_id):
        from app.services.scan_runner import execute_scan
        execute_scan(scan_id)
        return "sync"

    jobs.enqueue_scan = _sync
    import app.api.scans as scans_api
    scans_api.enqueue_scan = _sync
    with TestClient(main.app) as c:
        yield c


def register(client, email, org="Acme Sec", pw="Str0ng!Passw0rd"):
    r = client.post("/api/auth/register", json={"email": email, "password": pw, "organization_name": org, "full_name": "T"})
    assert r.status_code == 201, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def zip_dir(src: Path, dest: Path, prefix: str = "repo-main/") -> Path:
    import zipfile
    with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as z:
        for p in src.rglob("*"):
            if p.is_file():
                z.write(p, prefix + p.relative_to(src).as_posix())
    return dest
