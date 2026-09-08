#!/usr/bin/env sh
# POSIX entrypoint for the cross-platform repository check.
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)
exec python3 "$repo_root/scripts/core/repo_checks.py" oci
