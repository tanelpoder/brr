#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
BUILDER_IMAGE=${BRR_BUILDER_IMAGE:-brr-rhel8-builder:8.10}
RUNTIME_IMAGE=${BRR_RUNTIME_IMAGE:-registry.access.redhat.com/ubi8/ubi-minimal:8.10}

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
    for candidate in docker podman; do
        if command -v "$candidate" >/dev/null 2>&1 && "$candidate" info >/dev/null 2>&1; then
            printf '%s\n' "$candidate"
            return
        fi
    done
    echo "Docker or Podman is required; set CONTAINER_ENGINE to override detection" >&2
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
        ;;
    aarch64 | arm64)
        ARTIFACT_ARCH=aarch64
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
    uv sync --locked --all-groups --python /usr/bin/python3.11
    uv run --no-sync ruff check .
    uv run --no-sync ruff format --check .
    uv run --no-sync python -m pytest -q
    uv run --no-sync python scripts/build_release.py --binary --rhel8-compatible
'

mapfile -t artifacts < <(
    find "$ROOT/dist/release" -maxdepth 1 -type f -name "brr-*-linux-$ARTIFACT_ARCH" -print
)
if ((${#artifacts[@]} != 1)); then
    echo "expected one $ARTIFACT_ARCH standalone binary, found ${#artifacts[@]}" >&2
    exit 1
fi
artifact=${artifacts[0]}

runtime_options=(run --rm --security-opt label=disable -v "$artifact:/opt/brr:ro")
echo "+ $ENGINE run $RUNTIME_IMAGE /opt/brr --version"
"$ENGINE" "${runtime_options[@]}" "$RUNTIME_IMAGE" /opt/brr --version
atomic_debug=$(
    "$ENGINE" run --rm --security-opt label=disable \
        -e LD_DEBUG=libs \
        -v "$artifact:/opt/brr:ro" \
        "$RUNTIME_IMAGE" /opt/brr --version 2>&1
)
if [[ $atomic_debug != *"/libatomic.so.1"* ]]; then
    echo "clean runtime did not load bundled libatomic.so.1" >&2
    exit 1
fi
echo "+ $ENGINE run $RUNTIME_IMAGE /opt/brr --help"
"$ENGINE" "${runtime_options[@]}" "$RUNTIME_IMAGE" /opt/brr --help >/dev/null

echo "RHEL 8 compatible release binary: ${artifact#"$ROOT/"}"
echo "Checksum manifest: dist/release/SHA256SUMS"
