import zipfile
from pathlib import Path

import pytest

from app.scanner.workspace import UnsafeArchive, safe_extract_zip
from app.security import decrypt_secret, encrypt_secret


def _zip(path: Path, entries: dict[str, bytes]):
    with zipfile.ZipFile(path, "w") as z:
        for n, d in entries.items():
            z.writestr(n, d)
    return path


def test_zip_slip_rejected(tmp_path):
    z = _zip(tmp_path / "a.zip", {"../evil.txt": b"x"})
    with pytest.raises(UnsafeArchive):
        safe_extract_zip(z, tmp_path / "out", 10**7, 100)
    assert not (tmp_path / "evil.txt").exists()


def test_absolute_path_rejected(tmp_path):
    z = _zip(tmp_path / "a.zip", {"C:/Windows/evil.txt": b"x"})
    with pytest.raises(UnsafeArchive):
        safe_extract_zip(z, tmp_path / "out", 10**7, 100)


def test_size_limit(tmp_path):
    z = _zip(tmp_path / "a.zip", {"big.bin": b"0" * 2_000_000})
    with pytest.raises(UnsafeArchive):
        safe_extract_zip(z, tmp_path / "out", 1_000_000, 100)


def test_file_count_limit(tmp_path):
    z = _zip(tmp_path / "a.zip", {f"f{i}.txt": b"x" for i in range(20)})
    with pytest.raises(UnsafeArchive):
        safe_extract_zip(z, tmp_path / "out", 10**7, 10)


def test_single_root_stripped_and_symlink_skipped(tmp_path):
    p = tmp_path / "a.zip"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("repo-main/.github/workflows/ci.yml", "on: push\njobs: {}\n")
        info = zipfile.ZipInfo("repo-main/link")
        info.external_attr = (0o120777 << 16)
        z.writestr(info, "/etc/passwd")
    root = safe_extract_zip(p, tmp_path / "out", 10**7, 100)
    assert (root / ".github/workflows/ci.yml").is_file()
    assert not (root / "link").exists()


def test_not_a_zip(tmp_path):
    p = tmp_path / "x.zip"
    p.write_bytes(b"not a zip")
    with pytest.raises(UnsafeArchive):
        safe_extract_zip(p, tmp_path / "out", 10**7, 100)


def test_credential_encryption_roundtrip():
    tok = "ghp_example_token_value_1234"
    enc = encrypt_secret(tok)
    assert tok not in enc and decrypt_secret(enc) == tok
