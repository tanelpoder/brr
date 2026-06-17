# Packaging

This project builds release artifacts locally from the current checkout. The
standalone binary is produced with PyInstaller and is native to the build
machine architecture. Build x86_64 artifacts on x86_64, and build aarch64
artifacts on aarch64 unless real cross-build support is added and verified.

Do not relabel a native binary as another architecture. For example, running
`rpmbuild --target aarch64` on an x86_64 PyInstaller binary would create an
aarch64-labeled package with the wrong payload.

## Build Dependencies

Install `uv` first:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

On RHEL 8 or compatible systems, install the native packaging tools:

```bash
sudo dnf install rpm-build rpm cpio dpkg
```

The `dpkg` package may require EPEL or an equivalent vendor repository on some
RHEL-compatible distributions.

On Ubuntu or Debian systems, install:

```bash
sudo apt-get update
sudo apt-get install rpm dpkg cpio
```

`dpkg` is usually already present on Debian-family systems. The project package
dependencies are managed by `uv`.

## Build Artifacts

From a clean checkout:

```bash
uv sync --group dev --group package
uv run --group package python scripts/build_release.py --all
```

Artifacts are written to `dist/release/`:

- `brr-<version>-linux-<arch>`
- `brr_<version>-1_<deb-arch>.deb`
- `brr-<version>-1.<rpm-arch>.rpm`
- `SHA256SUMS`

On x86_64 Linux, the expected architecture names are:

- standalone binary: `x86_64`
- DEB: `amd64`
- RPM: `x86_64`

## Verify Artifacts

Check the standalone binary:

```bash
file dist/release/brr-*-linux-*
dist/release/brr-*-linux-* --version
```

Inspect the DEB:

```bash
dpkg-deb --info dist/release/*.deb
dpkg-deb --contents dist/release/*.deb
```

Inspect the RPM:

```bash
rpm -qip dist/release/*.rpm
rpm -qpl dist/release/*.rpm
```

Confirm package payload binaries match the expected architecture:

```bash
tmpdir=$(mktemp -d)
dpkg-deb -x dist/release/*.deb "$tmpdir"
file "$tmpdir/usr/bin/brr"
"$tmpdir/usr/bin/brr" --version
rm -rf "$tmpdir"

tmpdir=$(mktemp -d)
(cd "$tmpdir" && rpm2cpio /path/to/brr/dist/release/*.rpm | cpio -idm --quiet)
file "$tmpdir/usr/bin/brr"
"$tmpdir/usr/bin/brr" --version
rm -rf "$tmpdir"
```

Check checksums:

```bash
cd dist/release
sha256sum -c SHA256SUMS
```

## Pre-release Checks

Run the project checks before building release artifacts:

```bash
uv run ruff check .
uv run ruff format --check .
uv run python -m pytest -q
```
