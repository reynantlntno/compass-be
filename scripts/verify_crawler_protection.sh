#!/usr/bin/env bash
# Read-only repository guard for the COMPASS crawler-protection contract.
set -euo pipefail

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
failures=0

fail() {
  echo "FAIL: $1" >&2
  failures=$((failures + 1))
}

require_match() {
  pattern=$1
  path=$2
  if ! rg -q --fixed-strings -- "$pattern" "$repo_root/$path"; then
    fail "$path is missing the crawler-protection contract: $pattern"
  fi
}

require_match 'path("robots.txt", robots_txt, name="robots-txt")' config/urls.py
require_match 'Disallow: /' apps/system/http.py
require_match 'Disallow: /api/' apps/system/http.py
require_match 'Disallow: /admin/' apps/system/http.py
require_match 'Disallow: /docs/' apps/system/http.py
require_match 'Disallow: /openapi.json' apps/system/http.py
require_match 'apply_noindex_header(response)' apps/common/api/middleware.py
require_match '"X-Robots-Tag": NOINDEX_ROBOTS_TAG' apps/common/api/errors.py
require_match '"/api/v1/files/"' apps/common/api/middleware.py
require_match 'add_header X-Robots-Tag "noindex, nofollow, noarchive" always;' deploy/nginx/compass.conf
require_match 'signed branding-content path' docs/DEPLOYMENT_CRAWLER_PROTECTION.md

if rg -n '^[[:space:]]*autoindex[[:space:]]+on' deploy/nginx/compass.conf; then
  fail "Nginx directory listing is enabled."
fi
if rg -n '^[[:space:]]*Sitemap:' apps/system/http.py; then
  fail "robots.txt must not advertise a sitemap."
fi

if [ "$failures" -ne 0 ]; then
  echo "Crawler-protection guard failed with $failures issue(s)." >&2
  exit 1
fi

echo "Crawler-protection guard passed."
