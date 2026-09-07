#!/usr/bin/env bash
# POSIX convenience wrapper for the portable Python runtime helper.  The
# helper keeps the Django API service inside the configured web container and
# is shared with the PowerShell wrapper used on Windows.
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec python3 "$script_dir/compass_runtime.py" manage "$@"
