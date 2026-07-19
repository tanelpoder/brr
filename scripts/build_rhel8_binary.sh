#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)

echo "build_rhel8_binary.sh now builds the complete GLIBC 2.28 release." >&2
exec "$ROOT/scripts/build_rhel8_release.sh" "$@"
