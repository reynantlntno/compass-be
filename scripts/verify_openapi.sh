#!/usr/bin/env bash
# Read-only guard for the checked-in native OpenAPI document.
set -euo pipefail

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
cd "$repo_root"

./scripts/manage.sh export_openapi \
  --check \
  --output frontend/openapi/compass-api.json
