# Packaging

`brr` has two release workflows:

- The container build produces native standalone, RPM, and DEB artifacts with
  GLIBC 2.28 compatibility. Use this for published Linux releases.
- The native build uses the current host and is convenient for local packages.
  Its artifacts inherit the host's GLIBC requirement and may not run on older
  distributions.

PyInstaller is not a cross-compiler. Run either workflow independently on an
x86_64 host and an aarch64 host. Do not build through CPU emulation or relabel
an artifact for a different architecture.

## GLIBC 2.28 Container Build

The release builder uses Red Hat UBI 8.10 as the ABI baseline. UBI 8 supplies
GLIBC 2.28 on both supported architectures, so the resulting executable runs on
RHEL 8 and compatible distributions as well as newer Linux systems. The same
verified executable is placed in the standalone artifact, RPM, and DEB.

The builder currently contains:

- UBI 8.10 and its RHEL 8 RPM tooling
- UBI Python 3.11
- GCC Toolset 15 and binutils 2.44
- EPEL 8 `dpkg-deb` for Debian package assembly
- uv 0.11.29 and the versions locked in `uv.lock`, including PyInstaller 6.21

The compiler and Python headers are available if a locked dependency needs a
source build. Binary wheels are still used when the lockfile selects them. The
newer compiler does not change the GLIBC baseline because it runs and links in
the UBI 8 environment.

### Host dependencies

The host needs a native Linux installation, network access, and either Podman
or Docker. Python, uv, compilers, RPM tools, and DEB tools are installed inside
the builder image. Allow access to the Red Hat, Fedora/EPEL, GitHub Container
Registry, Python package, and Docker Hub registries.

On RHEL, Fedora, or a compatible distribution:

```bash
sudo dnf install podman
```

On Ubuntu or Debian, Podman is the simplest rootless option:

```bash
sudo apt-get update
sudo apt-get install podman
```

Docker from the distribution repository also works:

```bash
sudo apt-get update
sudo apt-get install docker.io
sudo systemctl enable --now docker
sudo usermod -aG docker "$USER"
```

Log out and back in after adding the Docker group. Run the build as the normal
checkout owner so bind-mounted artifacts are not written as root.

The script detects a working engine, preferring Podman. Select one explicitly
when both are installed:

```bash
CONTAINER_ENGINE=podman scripts/build_rhel8_release.sh
CONTAINER_ENGINE=docker scripts/build_rhel8_release.sh
```

### Build all release artifacts

Start from a clean checkout on the native build machine:

```bash
scripts/build_rhel8_release.sh
```

The command performs these mandatory gates:

1. Confirms the container and host architectures match and GLIBC is 2.28.
2. Reports the Python, compiler, binutils, RPM, DEB, and uv versions.
3. Syncs the lockfile and runs Ruff, the format check, and all unit tests.
4. Builds the PyInstaller executable, RPM, and DEB from one payload.
5. Inspects every bundled ELF for architecture and GLIBC symbol versions.
6. Confirms the package payloads are byte-identical to the standalone binary.
7. Installs and smoke-tests the RPM on UBI 8.10 and the DEB on Debian 10 and
   Ubuntu 20.04.
8. Verifies the checksum manifest.

The ELF check rejects GLIBC symbol requirements newer than 2.28, a mismatched
architecture, or a bundle without `libatomic.so.1`. The runtime checks exercise
`--version` and `--help`; live eBPF operations still require an appropriate
kernel and privileges.

Artifacts are written to `dist/release/`:

- `brr-<version>-linux-x86_64` or `brr-<version>-linux-aarch64`
- `brr-<version>-1.el8.x86_64.rpm` or `brr-<version>-1.el8.aarch64.rpm`
- `brr_<version>-1_amd64.deb` or `brr_<version>-1_arm64.deb`
- `SHA256SUMS`

Image names can be overridden for local mirrors:

```bash
BRR_BUILDER_IMAGE=example/brr-builder:8 \
BRR_RHEL_RUNTIME_IMAGE=example/ubi8-minimal:8.10 \
BRR_DEBIAN_RUNTIME_IMAGE=example/debian:buster \
BRR_UBUNTU_RUNTIME_IMAGE=example/ubuntu:20.04 \
scripts/build_rhel8_release.sh
```

The old `scripts/build_rhel8_binary.sh` entrypoint remains as a wrapper and now
builds the complete release.

### Repeat on x86_64 Ubuntu 24.04

Use a native x86_64 checkout and run the same commands:

```bash
sudo apt-get update
sudo apt-get install podman
git clone https://github.com/tanelpoder/brr.git
cd brr
scripts/build_rhel8_release.sh
```

The script derives RPM, DEB, and artifact architecture names from `uname -m`.
No `--platform`, QEMU, or other cross-build option is needed or supported.

## Verify Artifacts Manually

The release script already runs these checks. They can also be repeated on the
host when the relevant tools are installed:

```bash
file dist/release/brr-*-linux-*
rpm -qip dist/release/*.rpm
dpkg-deb --info dist/release/*.deb

cd dist/release
sha256sum -c SHA256SUMS
```

The standalone bundle supplies Python, application dependencies, and
`libatomic.so.1`. GLIBC remains a system library. GLIBC compatibility does not
guarantee that every operation works on an old kernel; the corresponding eBPF
commands, perf facilities, kernel configuration, and privileges must also be
available.

## Simple Native Build

Use this path when packages only need to run on the current machine or on hosts
with an equal or newer GLIBC. Install uv plus the native package tools.

On RHEL-family systems:

```bash
# Enable the matching EPEL repository first when dpkg is not already available.
# For RHEL 8 and compatible distributions:
sudo dnf install \
  https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm
sudo dnf install rpm-build rpm cpio dpkg binutils
```

On Debian-family systems:

```bash
sudo apt-get update
sudo apt-get install rpm dpkg cpio binutils
```

Build and test from the checkout:

```bash
uv sync --group dev --group package
uv run ruff check .
uv run ruff format --check .
uv run python -m pytest -q
uv run --group package python scripts/build_release.py --all
```

The same `dist/release/` names are used, but this command does not assert a
GLIBC 2.28 ceiling. Add `--binary`, `--rpm`, or `--deb` to build only selected
artifact types.
