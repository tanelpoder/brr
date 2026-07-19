from __future__ import annotations

from pathlib import Path

import pytest

from scripts import build_release


class FakeArchiveReader:
    def __init__(self, entries: dict[str, bytes]) -> None:
        self.toc = entries
        self._entries = entries

    def extract(self, name: str) -> bytes:
        return self._entries[name]


def elf(machine: int, *, byteorder: str = "little") -> bytes:
    data = bytearray(20)
    data[:4] = build_release.ELF_MAGIC
    data[5] = 1 if byteorder == "little" else 2
    data[18:20] = machine.to_bytes(2, byteorder=byteorder)
    return bytes(data)


def write_binary(tmp_path: Path, *, machine: int = 62) -> Path:
    binary = tmp_path / "brr"
    binary.write_bytes(elf(machine))
    return binary


def test_parse_glibc_versions_compares_numeric_components() -> None:
    versions = build_release.parse_glibc_versions(
        "Name: GLIBC_2.9 Flags: none\nName: GLIBC_2.28 Flags: none\nGLIBC_2.2.5"
    )

    assert versions == {(2, 9), (2, 28), (2, 2, 5)}
    assert max(versions) == (2, 28)


def test_read_elf_machine_supports_both_byte_orders() -> None:
    assert build_release.read_elf_machine(elf(62)) == 62
    assert build_release.read_elf_machine(elf(183, byteorder="big")) == 183
    assert build_release.read_elf_machine(b"not an ELF") is None


def test_collect_elf_payloads_includes_outer_and_embedded_elfs(tmp_path: Path) -> None:
    binary = write_binary(tmp_path)
    reader = FakeArchiveReader(
        {
            "libatomic.so.1": elf(62),
            "base_library.zip": b"not an ELF",
        }
    )

    payloads = build_release.collect_elf_payloads(binary, archive_reader=reader)

    assert [name for name, _data in payloads] == ["outer executable", "libatomic.so.1"]


def test_rhel8_verifier_accepts_matching_elfs(monkeypatch, tmp_path: Path, capsys) -> None:
    binary = write_binary(tmp_path)
    reader = FakeArchiveReader({"libatomic.so.1": elf(62), "extension.so": elf(62)})
    versions = {
        "outer executable": {(2, 14)},
        "libatomic.so.1": {(2, 28)},
        "extension.so": {(2, 2, 5)},
    }
    monkeypatch.setattr(
        build_release,
        "read_glibc_versions",
        lambda _data, *, display_name: versions[display_name],
    )

    build_release.verify_rhel8_compatibility(
        binary,
        build_release.ARCHITECTURES["x86_64"],
        archive_reader=reader,
    )

    output = capsys.readouterr().out
    assert "Verified 3 ELF files" in output
    assert "GLIBC_2.28" in output
    assert "bundled libatomic.so.1" in output


def test_rhel8_verifier_rejects_new_glibc_and_wrong_architecture(
    monkeypatch, tmp_path: Path
) -> None:
    binary = write_binary(tmp_path)
    reader = FakeArchiveReader({"libatomic.so.1": elf(183), "extension.so": elf(62)})
    versions = {
        "outer executable": {(2, 14)},
        "libatomic.so.1": {(2, 17)},
        "extension.so": {(2, 34)},
    }
    monkeypatch.setattr(
        build_release,
        "read_glibc_versions",
        lambda _data, *, display_name: versions[display_name],
    )

    with pytest.raises(SystemExit) as error:
        build_release.verify_rhel8_compatibility(
            binary,
            build_release.ARCHITECTURES["x86_64"],
            archive_reader=reader,
        )

    message = str(error.value)
    assert "libatomic.so.1 uses ELF machine 183, expected 62" in message
    assert "extension.so requires GLIBC_2.34" in message


def test_rhel8_verifier_requires_bundled_libatomic(monkeypatch, tmp_path: Path) -> None:
    binary = write_binary(tmp_path)
    reader = FakeArchiveReader({"extension.so": elf(62)})
    monkeypatch.setattr(build_release, "read_glibc_versions", lambda *_args, **_kwargs: set())

    with pytest.raises(SystemExit, match="missing bundled library: libatomic.so.1"):
        build_release.verify_rhel8_compatibility(
            binary,
            build_release.ARCHITECTURES["x86_64"],
            archive_reader=reader,
        )


def test_deb_control_declares_glibc_228_floor_and_runtime_libraries() -> None:
    metadata = build_release.ProjectMetadata(version="1.2.3", description="Test package")

    control = build_release.deb_control(metadata, build_release.ARCHITECTURES["aarch64"])

    assert "Architecture: arm64" in control
    assert "Depends: libc6 (>= 2.28), zlib1g, libatomic1" in control


def test_rpm_spec_declares_rhel8_runtime_requirements() -> None:
    metadata = build_release.ProjectMetadata(version="1.2.3", description="Test package")

    spec = build_release.rpm_spec(metadata)

    assert "%global __strip /bin/true" in spec
    assert "Requires:       glibc >= 2.28" in spec
    assert "Requires:       libatomic" in spec
    assert "Requires:       zlib" in spec
