from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

PROJECT = "brr"
PACKAGE_RELEASE = "1"
CHECKSUM_FILE = "SHA256SUMS"


def main() -> int:
    args = parse_args()
    try:
        artifacts = assemble_release(args.directory, args.version)
    except ValueError as error:
        raise SystemExit(str(error)) from error
    print(f"Assembled {len(artifacts)} release artifacts in {args.directory}")
    print(f"  {args.directory / CHECKSUM_FILE}")
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate a two-architecture brr release and write its checksums."
    )
    parser.add_argument("directory", type=Path, help="Directory containing all release artifacts.")
    parser.add_argument("--version", required=True, help="Release version without the leading v.")
    return parser.parse_args()


def expected_artifact_names(version: str) -> tuple[str, ...]:
    invalid_version = (
        not version
        or Path(version).name != version
        or any(character.isspace() for character in version)
    )
    if invalid_version:
        raise ValueError(f"invalid release version: {version!r}")
    return tuple(
        sorted(
            (
                f"{PROJECT}-{version}-linux-aarch64",
                f"{PROJECT}-{version}-linux-x86_64",
                f"{PROJECT}-{version}-{PACKAGE_RELEASE}.el8.aarch64.rpm",
                f"{PROJECT}-{version}-{PACKAGE_RELEASE}.el8.x86_64.rpm",
                f"{PROJECT}_{version}-{PACKAGE_RELEASE}_arm64.deb",
                f"{PROJECT}_{version}-{PACKAGE_RELEASE}_amd64.deb",
            )
        )
    )


def assemble_release(directory: Path, version: str) -> list[Path]:
    if not directory.is_dir():
        raise ValueError(f"release directory does not exist: {directory}")

    expected = set(expected_artifact_names(version))
    entries = {path.name: path for path in directory.iterdir() if path.name != CHECKSUM_FILE}
    actual = set(entries)
    missing = sorted(expected - actual)
    unexpected = sorted(actual - expected)
    if missing or unexpected:
        details = []
        if missing:
            details.append(f"missing: {', '.join(missing)}")
        if unexpected:
            details.append(f"unexpected: {', '.join(unexpected)}")
        raise ValueError("invalid release artifact set; " + "; ".join(details))

    artifacts = [entries[name] for name in sorted(expected)]
    invalid = [path.name for path in artifacts if path.is_symlink() or not path.is_file()]
    if invalid:
        raise ValueError(f"release artifacts must be regular files: {', '.join(invalid)}")
    empty = [path.name for path in artifacts if path.stat().st_size == 0]
    if empty:
        raise ValueError(f"release artifacts must not be empty: {', '.join(empty)}")

    lines = [f"{sha256(artifact)}  {artifact.name}" for artifact in artifacts]
    (directory / CHECKSUM_FILE).write_text("\n".join(lines) + "\n", encoding="utf-8")
    return artifacts


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as artifact_file:
        for chunk in iter(lambda: artifact_file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


if __name__ == "__main__":
    raise SystemExit(main())
