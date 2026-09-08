#!/usr/bin/env sh
# POSIX entrypoint for the cross-platform OCI release helper.
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd -P)
exec python3 "$repo_root/scripts/core/release.py" build "$@"
