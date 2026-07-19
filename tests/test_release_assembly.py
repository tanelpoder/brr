from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from scripts import assemble_release


def populate_release(tmp_path: Path, version: str = "1.2.3") -> tuple[str, ...]:
    names = assemble_release.expected_artifact_names(version)
    for index, name in enumerate(names, start=1):
        (tmp_path / name).write_bytes(f"artifact-{index}\n".encode())
    return names


def test_assemble_release_writes_sorted_checksums_for_exact_artifact_set(tmp_path: Path) -> None:
    names = populate_release(tmp_path)
    (tmp_path / "SHA256SUMS").write_text("stale manifest\n", encoding="utf-8")

    artifacts = assemble_release.assemble_release(tmp_path, "1.2.3")

    assert [artifact.name for artifact in artifacts] == list(names)
    lines = (tmp_path / "SHA256SUMS").read_text(encoding="utf-8").splitlines()
    expected = [
        f"{hashlib.sha256((tmp_path / name).read_bytes()).hexdigest()}  {name}" for name in names
    ]
    assert lines == expected


@pytest.mark.parametrize("problem", ["missing", "unexpected"])
def test_assemble_release_rejects_inexact_artifact_set(tmp_path: Path, problem: str) -> None:
    names = populate_release(tmp_path)
    if problem == "missing":
        (tmp_path / names[0]).unlink()
    else:
        (tmp_path / "notes.txt").write_text("not a release artifact", encoding="utf-8")

    with pytest.raises(ValueError, match=problem):
        assemble_release.assemble_release(tmp_path, "1.2.3")


def test_assemble_release_rejects_empty_artifact(tmp_path: Path) -> None:
    names = populate_release(tmp_path)
    (tmp_path / names[0]).write_bytes(b"")

    with pytest.raises(ValueError, match="must not be empty"):
        assemble_release.assemble_release(tmp_path, "1.2.3")


@pytest.mark.parametrize("version", ["", "../1.2.3", "1.2.3 bad"])
def test_expected_artifact_names_rejects_unsafe_versions(version: str) -> None:
    with pytest.raises(ValueError, match="invalid release version"):
        assemble_release.expected_artifact_names(version)
