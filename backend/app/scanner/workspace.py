"""Workspace preparation: safe archive extraction and file inventory. Repository code is never executed."""
from __future__ import annotations

import os
import stat
import zipfile
from pathlib import Path, PurePosixPath

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".tox", ".terraform", "dist", "build", ".next", "target"}

OTHER_CI_SYSTEMS = {
    ".gitlab-ci.yml": "GitLab CI", "Jenkinsfile": "Jenkins", "azure-pipelines.yml": "Azure DevOps Pipelines",
    "bitbucket-pipelines.yml": "Bitbucket Pipelines", ".circleci/config.yml": "CircleCI", ".travis.yml": "Travis CI",
    "cloudbuild.yaml": "Google Cloud Build", "buildspec.yml": "AWS CodeBuild", ".drone.yml": "Drone CI",
    "Taskfile.yml": "Task", ".buildkite/pipeline.yml": "Buildkite", "tekton": "Tekton",
}


class UnsafeArchive(Exception):
    pass


def safe_extract_zip(zip_path: Path, dest: Path, max_bytes: int, max_files: int, strip_single_root: bool = True) -> Path:
    """Extract a ZIP defensively: rejects path traversal, absolute paths, symlinks, and zip bombs.

    Returns the effective repository root (the single top-level folder of GitHub zipballs is stripped).
    """
    dest.mkdir(parents=True, exist_ok=True)
    dest_resolved = dest.resolve()
    total = 0
    count = 0
    try:
        zf = zipfile.ZipFile(zip_path)
    except zipfile.BadZipFile as exc:
        raise UnsafeArchive("not a valid ZIP archive") from exc
    with zf:
        infos = zf.infolist()
        if len(infos) > max_files:
            raise UnsafeArchive(f"archive has {len(infos)} entries (limit {max_files})")
        for info in infos:
            name = info.filename.replace("\\", "/")
            if not name or name.endswith("/"):
                continue
            pp = PurePosixPath(name)
            if pp.is_absolute() or ".." in pp.parts or (len(name) > 1 and name[1] == ":"):
                raise UnsafeArchive(f"unsafe path in archive: {name!r}")
            mode = (info.external_attr >> 16) & 0xFFFF
            if stat.S_ISLNK(mode):
                continue  # never materialize symlinks
            if any(part in SKIP_DIRS for part in pp.parts[:-1]):
                continue
            total += info.file_size
            if total > max_bytes:
                raise UnsafeArchive(f"archive expands beyond {max_bytes // (1024 * 1024)} MiB")
            if info.compress_size and info.file_size / max(info.compress_size, 1) > 1000 and info.file_size > 10 * 1024 * 1024:
                raise UnsafeArchive(f"suspicious compression ratio for {name!r}")
            target = (dest / Path(*pp.parts)).resolve()
            if not target.is_relative_to(dest_resolved):
                raise UnsafeArchive(f"path escapes workspace: {name!r}")
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, open(target, "wb") as out:
                written = 0
                while chunk := src.read(1024 * 256):
                    written += len(chunk)
                    if written > info.file_size + 1024:  # header lied about size
                        raise UnsafeArchive(f"entry {name!r} larger than declared")
                    out.write(chunk)
            os.chmod(target, 0o644)  # strip any executable bits
            count += 1
    if count == 0:
        raise UnsafeArchive("archive contains no files")
    if strip_single_root:
        entries = [p for p in dest.iterdir()]
        if len(entries) == 1 and entries[0].is_dir():
            return entries[0]
    return dest


def list_files(root: Path, limit: int = 100_000) -> list[str]:
    out: list[str] = []
    root = root.resolve()
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not os.path.islink(os.path.join(dirpath, d))]
        for fn in filenames:
            full = Path(dirpath) / fn
            if full.is_symlink():
                continue
            out.append(full.relative_to(root).as_posix())
            if len(out) >= limit:
                return sorted(out)
    return sorted(out)


def workflow_paths(files: list[str]) -> list[str]:
    return [f for f in files if f.startswith(".github/workflows/") and f.lower().endswith((".yml", ".yaml")) and f.count("/") == 2]


def detect_other_ci(files: list[str]) -> list[dict]:
    found = []
    fset = set(files)
    for marker, system in OTHER_CI_SYSTEMS.items():
        if marker in fset or (marker == "tekton" and any(f.startswith("tekton/") or "/tekton/" in f for f in files)):
            found.append({"system": system, "file": marker})
    return found
