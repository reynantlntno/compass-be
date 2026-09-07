#!/usr/bin/env sh
# POSIX convenience wrapper for the portable, container-aware API readiness runner.
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec python3 "$script_dir/compass_runtime.py" readiness "$@"
