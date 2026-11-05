from __future__ import annotations

from pathlib import Path

from ..config import get_settings
from ..scanner.model import RepoMetadata
from ..scanner.workspace import UnsafeArchive, safe_extract_zip
from .base import AcquiredWorkspace, Connector, ConnectorError


class UploadConnector(Connector):
    name = "upload"
    display_name = "Repository ZIP upload (offline)"

    def acquire(self, *, project, secret, workdir: Path, upload_path: Path | None, progress) -> AcquiredWorkspace:
        if not upload_path or not upload_path.exists():
            raise ConnectorError("uploaded archive not found")
        s = get_settings()
        progress("Extracting archive")
        try:
            root = safe_extract_zip(upload_path, workdir / "src", s.max_extracted_mb * 1024 * 1024, s.max_extracted_files)
        except UnsafeArchive as exc:
            raise ConnectorError(f"archive rejected: {exc}") from exc
        return AcquiredWorkspace(root=root, metadata=RepoMetadata(source="upload", full_name=project.name))
