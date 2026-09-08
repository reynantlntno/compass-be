#!/usr/bin/env sh
# POSIX convenience wrapper for the portable, container-aware API readiness runner.
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)
exec python3 "$repo_root/scripts/core/compass_runtime.py" readiness "$@"
