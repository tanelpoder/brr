#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
BUILDER_IMAGE=${BRR_BUILDER_IMAGE:-brr-rhel8-builder:8.10}
RHEL_RUNTIME_IMAGE=${BRR_RHEL_RUNTIME_IMAGE:-${BRR_RUNTIME_IMAGE:-registry.access.redhat.com/ubi8/ubi-minimal:8.10}}
DEBIAN_RUNTIME_IMAGE=${BRR_DEBIAN_RUNTIME_IMAGE:-docker.io/debian/eol:buster-slim}
UBUNTU_RUNTIME_IMAGE=${BRR_UBUNTU_RUNTIME_IMAGE:-docker.io/library/ubuntu:20.04}

find_container_engine() {
    if [[ -n ${CONTAINER_ENGINE:-} ]]; then
        if ! command -v "$CONTAINER_ENGINE" >/dev/null 2>&1; then
            echo "container engine not found: $CONTAINER_ENGINE" >&2
            return 1
        fi
        printf '%s\n' "$CONTAINER_ENGINE"
        return
    fi

    local candidate
    for candidate in podman docker; do
        if command -v "$candidate" >/dev/null 2>&1 && "$candidate" info >/dev/null 2>&1; then
            printf '%s\n' "$candidate"
            return
        fi
    done
    echo "Podman or Docker is required; set CONTAINER_ENGINE to override detection" >&2
    return 1
}

ENGINE=$(find_container_engine)
ENGINE_VERSION=$($ENGINE --version 2>/dev/null || true)
if [[ $ENGINE_VERSION == *[Pp]odman* ]]; then
    IS_PODMAN=1
else
    IS_PODMAN=0
fi

case $(uname -m) in
    x86_64 | amd64)
        ARTIFACT_ARCH=x86_64
        DEB_ARCH=amd64
        RPM_ARCH=x86_64
        ;;
    aarch64 | arm64)
        ARTIFACT_ARCH=aarch64
        DEB_ARCH=arm64
        RPM_ARCH=aarch64
        ;;
    *)
        echo "unsupported build architecture: $(uname -m)" >&2
        exit 1
        ;;
esac

echo "+ $ENGINE build -f Containerfile.rhel8 -t $BUILDER_IMAGE ."
"$ENGINE" build -f "$ROOT/Containerfile.rhel8" -t "$BUILDER_IMAGE" "$ROOT"

run_options=(
    run
    --rm
    --security-opt label=disable
    -e HOME=/tmp
    -e BRR_EXPECTED_ARCH="$ARTIFACT_ARCH"
    -e UV_CACHE_DIR=/tmp/uv-cache
    -e UV_PROJECT_ENVIRONMENT=/tmp/brr-venv
    -v "$ROOT:/workspace"
)
if ((IS_PODMAN)); then
    run_options+=(--userns=keep-id)
else
    run_options+=(--user "$(id -u):$(id -g)")
fi

echo "+ $ENGINE run $BUILDER_IMAGE (checks and native release build)"
"$ENGINE" "${run_options[@]}" "$BUILDER_IMAGE" bash -lc '
    set -euo pipefail
    test "$(getconf GNU_LIBC_VERSION)" = "glibc 2.28"
    case $(uname -m) in
        x86_64 | amd64) container_arch=x86_64 ;;
        aarch64 | arm64) container_arch=aarch64 ;;
        *) echo "unsupported container architecture: $(uname -m)" >&2; exit 1 ;;
    esac
    test "$container_arch" = "$BRR_EXPECTED_ARCH"
    python3.11 --version
    gcc --version | head -n 1
    ld --version | head -n 1
    rpmbuild --version
    dpkg-deb --version | head -n 1
    uv --version
    uv sync --locked --all-groups --python /usr/bin/python3.11
    uv run --no-sync ruff check .
    uv run --no-sync ruff format --check .
    uv run --no-sync python -m pytest -q
    uv run --no-sync python scripts/build_release.py --all --rhel8-compatible
'

mapfile -t binaries < <(
    find "$ROOT/dist/release" -maxdepth 1 -type f -name "brr-*-linux-$ARTIFACT_ARCH" -print
)
mapfile -t debs < <(
    find "$ROOT/dist/release" -maxdepth 1 -type f -name "brr_*_${DEB_ARCH}.deb" -print
)
mapfile -t rpms < <(
    find "$ROOT/dist/release" -maxdepth 1 -type f -name "brr-*.$RPM_ARCH.rpm" -print
)
if ((${#binaries[@]} != 1 || ${#debs[@]} != 1 || ${#rpms[@]} != 1)); then
    echo "expected one standalone binary, DEB, and RPM for $ARTIFACT_ARCH" >&2
    exit 1
fi
binary=${binaries[0]}
deb=${debs[0]}
rpm=${rpms[0]}
container_binary=/workspace/dist/release/$(basename "$binary")
container_deb=/workspace/dist/release/$(basename "$deb")
container_rpm=/workspace/dist/release/$(basename "$rpm")

verify_options=(
    run
    --rm
    --security-opt label=disable
    -v "$ROOT:/workspace:ro"
)
echo "+ verify package metadata and byte-identical payloads"
"$ENGINE" "${verify_options[@]}" "$BUILDER_IMAGE" bash -lc "
    set -euo pipefail
    test \"\$(dpkg-deb --field '$container_deb' Architecture)\" = '$DEB_ARCH'
    test \"\$(rpm -qp --queryformat '%{ARCH}' '$container_rpm')\" = '$RPM_ARCH'
    tmp=\$(mktemp -d)
    trap 'rm -rf \"\$tmp\"' EXIT
    dpkg-deb --extract '$container_deb' \"\$tmp/deb\"
    cd \"\$tmp\"
    rpm2cpio '$container_rpm' | cpio -idm --quiet
    cmp '$container_binary' \"\$tmp/deb/usr/bin/brr\"
    cmp '$container_binary' \"\$tmp/usr/bin/brr\"
    cd /workspace/dist/release
    sha256sum -c SHA256SUMS
"

runtime_options=(run --rm --security-opt label=disable)
echo "+ $ENGINE run $RHEL_RUNTIME_IMAGE (standalone smoke test)"
"$ENGINE" "${runtime_options[@]}" -v "$binary:/opt/brr:ro" \
    "$RHEL_RUNTIME_IMAGE" /opt/brr --version
atomic_debug=$(
    "$ENGINE" "${runtime_options[@]}" -e LD_DEBUG=libs -v "$binary:/opt/brr:ro" \
        "$RHEL_RUNTIME_IMAGE" /opt/brr --version 2>&1
)
if [[ $atomic_debug != *"/libatomic.so.1"* ]]; then
    echo "clean runtime did not load bundled libatomic.so.1" >&2
    exit 1
fi
"$ENGINE" "${runtime_options[@]}" -v "$binary:/opt/brr:ro" \
    "$RHEL_RUNTIME_IMAGE" /opt/brr --help >/dev/null

echo "+ $ENGINE run $RHEL_RUNTIME_IMAGE (RPM install smoke test)"
"$ENGINE" "${runtime_options[@]}" -v "$rpm:/tmp/brr.rpm:ro" "$RHEL_RUNTIME_IMAGE" sh -lc '
    set -e
    microdnf install -y glibc libatomic zlib
    rpm -Uvh /tmp/brr.rpm
    brr --version
    brr --help >/dev/null
'

smoke_test_deb() {
    local image=$1
    local expected_glibc=$2
    echo "+ $ENGINE run $image (DEB install smoke test)"
    "$ENGINE" "${runtime_options[@]}" -e BRR_EXPECTED_GLIBC="$expected_glibc" \
        -v "$deb:/tmp/brr.deb:ro" "$image" bash -lc '
        set -e
        test "$(getconf GNU_LIBC_VERSION)" = "$BRR_EXPECTED_GLIBC"
        apt-get update
        DEBIAN_FRONTEND=noninteractive apt-get install -y /tmp/brr.deb
        brr --version
        brr --help >/dev/null
    '
}

smoke_test_deb "$DEBIAN_RUNTIME_IMAGE" "glibc 2.28"
smoke_test_deb "$UBUNTU_RUNTIME_IMAGE" "glibc 2.31"

echo "RHEL 8 / GLIBC 2.28 compatible release artifacts:"
printf '  %s\n' "${binary#"$ROOT/"}" "${deb#"$ROOT/"}" "${rpm#"$ROOT/"}"
echo "  dist/release/SHA256SUMS"
