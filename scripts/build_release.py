from __future__ import annotations

import argparse
import hashlib
import os
import platform
import shutil
import subprocess
import sys
import tomllib
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

PROJECT = "brr"
PACKAGE_RELEASE = "1"
MAINTAINER = "Tanel Poder <tanel@tanelpoder.com>"
LICENSE = "MIT"
ROOT = Path(__file__).resolve().parents[1]
BUILD_DIR = ROOT / "build" / "release"
DIST_DIR = ROOT / "dist" / "release"
PYINSTALLER_DIR = ROOT / "build" / "pyinstaller"
ENTRYPOINT = ROOT / "scripts" / "pyinstaller_entrypoint.py"
DOC_FILES = ("README.md",)


@dataclass(frozen=True)
class Architecture:
    artifact: str
    deb: str
    rpm: str


ARCHITECTURES = {
    "x86_64": Architecture(artifact="x86_64", deb="amd64", rpm="x86_64"),
    "amd64": Architecture(artifact="x86_64", deb="amd64", rpm="x86_64"),
    "aarch64": Architecture(artifact="aarch64", deb="arm64", rpm="aarch64"),
    "arm64": Architecture(artifact="aarch64", deb="arm64", rpm="aarch64"),
}


@dataclass(frozen=True)
class ProjectMetadata:
    version: str
    description: str


def main() -> int:
    args = parse_args()
    targets = selected_targets(args)
    metadata = read_project_metadata()
    architecture = detect_architecture()

    ensure_tools(targets)
    prepare_output_dirs(clean=args.clean)

    binary = build_binary()
    smoke_test_binary(binary)

    artifacts: list[Path] = []
    if "binary" in targets:
        artifacts.append(build_binary_artifact(binary, metadata, architecture))
    if "deb" in targets:
        artifacts.append(build_deb(binary, metadata, architecture))
    if "rpm" in targets:
        artifacts.append(build_rpm(binary, metadata, architecture))

    write_checksums(artifacts)
    print("Built release artifacts:")
    for artifact in artifacts:
        print(f"  {artifact.relative_to(ROOT)}")
    print(f"  {(DIST_DIR / 'SHA256SUMS').relative_to(ROOT)}")
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build local brr release artifacts.")
    parser.add_argument(
        "--all",
        action="store_true",
        help="Build binary, DEB, and RPM artifacts. This is the default when no target is set.",
    )
    parser.add_argument(
        "--binary", action="store_true", help="Build the standalone binary artifact."
    )
    parser.add_argument("--deb", action="store_true", help="Build the DEB package.")
    parser.add_argument("--rpm", action="store_true", help="Build the RPM package.")
    parser.add_argument(
        "--no-clean",
        action="store_false",
        dest="clean",
        help="Reuse existing build directories instead of cleaning release output first.",
    )
    parser.set_defaults(clean=True)
    return parser.parse_args()


def selected_targets(args: argparse.Namespace) -> set[str]:
    if args.all or not (args.binary or args.deb or args.rpm):
        return {"binary", "deb", "rpm"}

    targets: set[str] = set()
    if args.binary:
        targets.add("binary")
    if args.deb:
        targets.add("deb")
    if args.rpm:
        targets.add("rpm")
    return targets


def read_project_metadata() -> ProjectMetadata:
    with (ROOT / "pyproject.toml").open("rb") as pyproject_file:
        project = tomllib.load(pyproject_file)["project"]
    return ProjectMetadata(
        version=project["version"],
        description=project["description"],
    )


def detect_architecture() -> Architecture:
    machine = platform.machine().lower()
    architecture = ARCHITECTURES.get(machine)
    if architecture is None:
        supported = ", ".join(sorted(ARCHITECTURES))
        raise SystemExit(f"unsupported architecture {machine!r}; supported: {supported}")
    return architecture


def ensure_tools(targets: set[str]) -> None:
    missing = []
    if "deb" in targets and shutil.which("dpkg-deb") is None:
        missing.append("dpkg-deb")
    if "rpm" in targets and shutil.which("rpmbuild") is None:
        missing.append("rpmbuild")
    if missing:
        raise SystemExit(f"missing required packaging tools: {', '.join(missing)}")


def prepare_output_dirs(*, clean: bool) -> None:
    if clean:
        shutil.rmtree(BUILD_DIR, ignore_errors=True)
        shutil.rmtree(DIST_DIR, ignore_errors=True)
        shutil.rmtree(PYINSTALLER_DIR, ignore_errors=True)
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    DIST_DIR.mkdir(parents=True, exist_ok=True)


def build_binary() -> Path:
    dist_path = PYINSTALLER_DIR / "dist"
    work_path = PYINSTALLER_DIR / "work"
    spec_path = PYINSTALLER_DIR / "spec"
    run(
        [
            sys.executable,
            "-m",
            "PyInstaller",
            "--clean",
            "--noconfirm",
            "--onefile",
            "--name",
            PROJECT,
            "--paths",
            str(ROOT / "src"),
            "--distpath",
            str(dist_path),
            "--workpath",
            str(work_path),
            "--specpath",
            str(spec_path),
            str(ENTRYPOINT),
        ]
    )
    binary = dist_path / PROJECT
    if not binary.exists():
        raise SystemExit(f"PyInstaller did not create expected binary: {binary}")
    binary.chmod(0o755)
    return binary


def smoke_test_binary(binary: Path) -> None:
    run([str(binary), "--help"], stdout=subprocess.DEVNULL)
    if shutil.which("ldd") is None:
        return

    result = subprocess.run(
        ["ldd", str(binary)],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    if "not found" in result.stdout or "not found" in result.stderr:
        raise SystemExit(f"binary has unresolved shared libraries:\n{result.stdout}{result.stderr}")


def build_binary_artifact(
    binary: Path,
    metadata: ProjectMetadata,
    architecture: Architecture,
) -> Path:
    artifact = DIST_DIR / f"{PROJECT}-{metadata.version}-linux-{architecture.artifact}"
    copy_binary(binary, artifact)
    return artifact


def build_deb(binary: Path, metadata: ProjectMetadata, architecture: Architecture) -> Path:
    package_name = f"{PROJECT}_{metadata.version}-{PACKAGE_RELEASE}_{architecture.deb}"
    staging = BUILD_DIR / "deb" / package_name
    shutil.rmtree(staging, ignore_errors=True)

    copy_binary(binary, staging / "usr" / "bin" / PROJECT)
    doc_dir = staging / "usr" / "share" / "doc" / PROJECT
    copy_docs(doc_dir)
    write_deb_copyright(doc_dir / "copyright")

    control_dir = staging / "DEBIAN"
    control_dir.mkdir(parents=True)
    (control_dir / "control").write_text(
        deb_control(metadata, architecture),
        encoding="utf-8",
    )
    normalize_permissions(staging, executable_paths={staging / "usr" / "bin" / PROJECT})

    artifact = DIST_DIR / f"{package_name}.deb"
    run(["dpkg-deb", "--build", "--root-owner-group", str(staging), str(artifact)])
    return artifact


def build_rpm(binary: Path, metadata: ProjectMetadata, architecture: Architecture) -> Path:
    rpm_root = BUILD_DIR / "rpm"
    sources = rpm_root / "SOURCES"
    specs = rpm_root / "SPECS"
    for directory in ("BUILD", "BUILDROOT", "RPMS", "SOURCES", "SPECS", "SRPMS", "rpmdb"):
        (rpm_root / directory).mkdir(parents=True, exist_ok=True)

    copy_binary(binary, sources / PROJECT)
    for doc_file in DOC_FILES:
        shutil.copy2(ROOT / doc_file, sources / doc_file)
    shutil.copy2(ROOT / "LICENSE", sources / "LICENSE")

    spec_file = specs / f"{PROJECT}.spec"
    spec_file.write_text(rpm_spec(metadata), encoding="utf-8")
    run(
        [
            "rpmbuild",
            "-bb",
            str(spec_file),
            "--target",
            architecture.rpm,
            "--define",
            f"_topdir {rpm_root}",
            "--define",
            f"_dbpath {rpm_root / 'rpmdb'}",
        ]
    )

    rpm_files = sorted((rpm_root / "RPMS" / architecture.rpm).glob("*.rpm"))
    if not rpm_files:
        raise SystemExit("rpmbuild completed without producing an RPM")

    artifact = DIST_DIR / rpm_files[-1].name
    shutil.copy2(rpm_files[-1], artifact)
    return artifact


def copy_binary(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    destination.chmod(0o755)


def copy_docs(destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    for doc_file in DOC_FILES:
        shutil.copy2(ROOT / doc_file, destination / doc_file)
    shutil.copy2(ROOT / "LICENSE", destination / "LICENSE")


def deb_control(metadata: ProjectMetadata, architecture: Architecture) -> str:
    return "\n".join(
        [
            f"Package: {PROJECT}",
            f"Version: {metadata.version}-{PACKAGE_RELEASE}",
            "Section: utils",
            "Priority: optional",
            f"Architecture: {architecture.deb}",
            "Depends: libc6, zlib1g",
            f"Maintainer: {MAINTAINER}",
            f"Description: {metadata.description}",
            " brr reports and profiles loaded Linux eBPF objects.",
            "",
        ]
    )


def write_deb_copyright(destination: Path) -> None:
    license_text = (ROOT / "LICENSE").read_text(encoding="utf-8")
    destination.write_text(
        "\n".join(
            [
                "Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/",
                f"Upstream-Name: {PROJECT}",
                "Source: https://github.com/tanelpoder/brr",
                "",
                "Files: *",
                "Copyright: 2026 Tanel Poder",
                f"License: {LICENSE}",
                indent_license(license_text),
                "",
            ]
        ),
        encoding="utf-8",
    )


def indent_license(license_text: str) -> str:
    lines = []
    for line in license_text.splitlines():
        lines.append(f" {line}" if line else " .")
    return "\n".join(lines)


def normalize_permissions(root: Path, *, executable_paths: set[Path]) -> None:
    executables = {path.resolve() for path in executable_paths}
    root.chmod(0o755)
    for path in root.rglob("*"):
        if path.is_dir():
            path.chmod(0o755)
        elif path.resolve() in executables:
            path.chmod(0o755)
        else:
            path.chmod(0o644)


def rpm_spec(metadata: ProjectMetadata) -> str:
    changelog_date = datetime.now(tz=UTC).strftime("%a %b %d %Y")
    doc_install_lines = "\n".join(
        f"install -D -m 0644 %{{_sourcedir}}/{doc_file} "
        f"%{{buildroot}}%{{_docdir}}/%{{name}}/{doc_file}"
        for doc_file in DOC_FILES
    )
    doc_file_lines = "\n".join(f"%doc %{{_docdir}}/%{{name}}/{doc_file}" for doc_file in DOC_FILES)
    return f"""Name:           {PROJECT}
Version:        {metadata.version}
Release:        {PACKAGE_RELEASE}%{{?dist}}
Summary:        {metadata.description}
License:        {LICENSE}
URL:            https://github.com/tanelpoder/brr

%description
brr reports and profiles loaded Linux eBPF objects.

%prep

%build

%install
rm -rf %{{buildroot}}
install -D -m 0755 %{{_sourcedir}}/{PROJECT} %{{buildroot}}%{{_bindir}}/{PROJECT}
{doc_install_lines}
install -D -m 0644 %{{_sourcedir}}/LICENSE %{{buildroot}}%{{_licensedir}}/%{{name}}/LICENSE

%files
%{{_bindir}}/{PROJECT}
{doc_file_lines}
%license %{{_licensedir}}/%{{name}}/LICENSE

%changelog
* {changelog_date} {MAINTAINER} - {metadata.version}-{PACKAGE_RELEASE}
- Local release build.
"""


def write_checksums(artifacts: list[Path]) -> None:
    lines = []
    for artifact in sorted(artifacts):
        digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
        lines.append(f"{digest}  {artifact.name}")
    (DIST_DIR / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")


def run(
    command: list[str],
    *,
    stdout: int | None = None,
) -> None:
    printable = " ".join(command)
    print(f"+ {printable}", flush=True)
    env = os.environ.copy()
    env.setdefault("PYTHONUNBUFFERED", "1")
    subprocess.run(command, cwd=ROOT, env=env, check=True, stdout=stdout)


if __name__ == "__main__":
    raise SystemExit(main())
