# Packaging

`brr` has two build paths:

- The container build produces native standalone, RPM, and DEB artifacts with
  GLIBC 2.28 compatibility. Use this for published Linux releases.
- The native build uses the current host and is convenient for local packages.
  Its artifacts inherit the host's GLIBC requirement and may not run on older
  distributions.

PyInstaller is not a cross-compiler. Run either workflow independently on an
x86_64 host and an aarch64 host. Do not build through CPU emulation or relabel
an artifact for a different architecture.

Official releases are assembled by GitHub Actions from native x86_64 and
aarch64 builds. The same container command remains available locally for
pre-release testing and as a manual fallback.

## Automated GitHub Releases

The `Release` workflow runs on version tags matching `vMAJOR.MINOR.PATCH`. It
uses native `ubuntu-24.04` and `ubuntu-24.04-arm` runners and executes
`scripts/build_rhel8_release.sh` independently on each architecture. The
workflow does not use emulation or cross-compilation. GitHub's hosted ARM64
runner is currently a public preview; the local aarch64 build remains the
fallback if that runner is temporarily unavailable.

Each build still passes all container checks documented below. The final job
requires the exact six standalone and package artifacts, writes one combined
`SHA256SUMS`, creates build-provenance attestations, uploads the seven files to
the matching GitHub release, and downloads them again to verify the published
bytes. The release remains a draft for manual review.

Prepare a release only after the version bump and local checks are committed:

```bash
git tag -a v0.6.0 -m "brr 0.6.0"
git push origin main
git push origin v0.6.0
```

Pushing a new version tag starts the workflow. To populate an existing draft
or retry an existing tag, dispatch it explicitly from the default branch:

```bash
gh workflow run release.yml --ref main -f tag=v0.6.0
gh run list --workflow release.yml --limit 5
run_id=$(gh run list --workflow release.yml --limit 1 --json databaseId \
  --jq '.[0].databaseId')
gh run watch "$run_id" --exit-status
```

Before publishing, download the draft assets and verify the combined manifest:

```bash
verify_dir=$(mktemp -d)
gh release download v0.6.0 --dir "$verify_dir"
(cd "$verify_dir" && sha256sum -c SHA256SUMS)
gh release view v0.6.0
```

Publish only after the draft notes and all seven assets have been reviewed:

```bash
gh release edit v0.6.0 --verify-tag --draft=false --latest
```

The workflow refuses to replace assets on a published release. A retry may
replace the complete asset set while the release is still a draft. With GitHub
release immutability enabled, publishing also locks the release assets and tag.

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
