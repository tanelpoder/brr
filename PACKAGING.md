# Packaging

Release binaries are built natively in a Red Hat UBI 8.10 container. This gives
PyInstaller a GLIBC 2.28 build environment on both supported architectures. Run
the build independently on an x86_64 machine and an aarch64 machine; PyInstaller
is not a cross-compiler, and the build script intentionally does not use CPU
emulation.

The container build produces the standalone binary intended for a GitHub
release. The existing native build command remains available for DEB and RPM
packages, but those package builds are separate from the GLIBC 2.28 binary
workflow.

## Host Dependencies

The host only needs a container engine and a working network connection to the
Red Hat, GitHub Container Registry, and Python package registries. Python, uv,
PyInstaller, `readelf`, and the RHEL build libraries are installed inside the
builder image.

On RHEL, Fedora, or a compatible distribution, Podman is the simplest option:

```bash
sudo dnf install podman
```

On Ubuntu or Debian, install Docker from the distribution packages:

```bash
sudo apt-get update
sudo apt-get install docker.io
```

Ensure the current user can run Docker, or run the build through a rootless
Podman installation. The script detects Docker or Podman automatically. To
select one explicitly:

```bash
CONTAINER_ENGINE=podman scripts/build_rhel8_binary.sh
CONTAINER_ENGINE=docker scripts/build_rhel8_binary.sh
```

The UBI builder installs these packages automatically:

- `python3.11`: the system CPython embedded by PyInstaller
- `binutils`: provides `readelf` for GLIBC symbol-version inspection
- `file`: provides manual ELF diagnostics
- `libatomic`: bundled for ordered perf ring access, especially on aarch64

A compiler toolchain, Python development headers, RPM tools, and DEB tools are
not required for the standalone binary build.

## Build RHEL 8 Compatible Binaries

Start from a clean checkout on each native machine and run:

```bash
scripts/build_rhel8_binary.sh
```

The script:

1. Builds `Containerfile.rhel8` for the machine's native architecture.
2. Uses UBI's `/usr/bin/python3.11`; uv-managed Python downloads are disabled.
3. Syncs the locked development and packaging dependencies.
4. Runs Ruff, the format check, and the complete unit test suite.
5. Builds the one-file PyInstaller binary and verifies all bundled ELF files.
6. Runs the finished binary in a fresh UBI 8 minimal runtime container.

The compatibility check fails the build if any outer or bundled ELF requires a
GLIBC symbol newer than 2.28, has the wrong architecture, or if
`libatomic.so.1` is not bundled. It also retains the `ldd`, `--help`, and
`--version` smoke checks. There is no release-build option to skip these gates.

Artifacts are written to `dist/release/`:

- x86_64: `brr-<version>-linux-x86_64`
- aarch64: `brr-<version>-linux-aarch64`
- checksum manifest: `SHA256SUMS`

The builder and runtime image names can be overridden for local mirrors:

```bash
BRR_BUILDER_IMAGE=example/brr-builder:8 \
BRR_RUNTIME_IMAGE=example/ubi8-minimal:8 \
scripts/build_rhel8_binary.sh
```

## Verify and Publish Artifacts

The build log reports the number of inspected ELF files and the highest GLIBC
symbol version found. It must report at most `GLIBC_2.28`.

Additional manual checks can be run on the host:

```bash
file dist/release/brr-*-linux-*
dist/release/brr-*-linux-* --version

cd dist/release
sha256sum -c SHA256SUMS
```

Upload the x86_64 artifact produced on the x86_64 machine and the aarch64
artifact produced on the aarch64 machine to the same GitHub release. Do not
rename an x86_64 payload as aarch64, or the reverse.

The standalone bundle supplies Python, application packages, and libatomic.
Standard RHEL 8 runtime libraries are still used, including GLIBC. GLIBC 2.28
compatibility does not imply that every brr operation works on every old
kernel: the relevant eBPF commands, perf facilities, privileges, and kernel
configuration must still be available.

## Native DEB and RPM Packages

The original package builder remains available when native DEB or RPM packages
are needed. Install uv and the packaging tools on that build host:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

On RHEL-family systems:

```bash
sudo dnf install rpm-build rpm cpio dpkg
```

On Debian-family systems:

```bash
sudo apt-get update
sudo apt-get install rpm dpkg cpio
```

Then build the native packages:

```bash
uv sync --group dev --group package
uv run --group package python scripts/build_release.py --all
```

These package commands use the host toolchain and system Python. Use the
containerized binary workflow above for the GitHub release binaries with the
enforced GLIBC 2.28 ceiling.
