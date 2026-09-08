#!/usr/bin/env bash
# POSIX convenience wrapper for the portable Python runtime helper.  The
# helper keeps the Django API service inside the configured web container and
# is shared with the PowerShell wrapper used on Windows.
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)
exec python3 "$repo_root/scripts/core/compass_runtime.py" manage "$@"
