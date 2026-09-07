#!/usr/bin/env bash
# Transfer exactly one verified staging package through an operator-provided
# SSH/Bastion path. This script never deletes remote files or runs deployment
# commands on the VM.
set -euo pipefail

usage() {
  echo "Usage: $0 --execute /path/release-dir user@host:/remote/path [-- scp-options ...]" >&2
}

if [ "$#" -lt 3 ] || [ "$1" != "--execute" ]; then
  usage
  echo "Refusing transfer without the explicit --execute switch." >&2
  exit 64
fi
shift

release_dir=$1
remote_target=$2
shift 2

case "$release_dir" in
  /*) ;;
  *) echo "Use an absolute release directory." >&2; exit 64 ;;
esac
repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)
case "$release_dir" in
  "$repo_root"|"$repo_root"/*)
    echo "The release directory must be outside the repository." >&2
    exit 64
    ;;
esac
case "$remote_target" in
  *:* ) ;;
  *) echo "Remote target must use user@host:/path syntax." >&2; exit 64 ;;
esac

scp_options=()
if [ "$#" -gt 0 ]; then
  [ "$1" = "--" ] || {
    usage
    echo "Additional scp options must follow --." >&2
    exit 64
  }
  shift
  scp_options=("$@")
fi

for artifact in \
  compass-staging-amd64.oci.tar \
  compass-staging-release.tar.gz \
  manifest.txt; do
  [ -f "$release_dir/$artifact" ] || {
    echo "Release artifact is missing: $release_dir/$artifact" >&2
    exit 78
  }
done

command -v scp >/dev/null 2>&1 || { echo "scp is required." >&2; exit 127; }

checksum_value() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    echo "Neither sha256sum nor shasum is available." >&2
    exit 127
  fi
}

expected_image_sha256=$(checksum_value "$release_dir/compass-staging-amd64.oci.tar")
expected_bundle_sha256=$(checksum_value "$release_dir/compass-staging-release.tar.gz")
grep -Fqx -- "image_sha256=$expected_image_sha256" "$release_dir/manifest.txt" || {
  echo "Image checksum does not match manifest.txt." >&2
  exit 78
}
grep -Fqx -- "release_bundle_sha256=$expected_bundle_sha256" "$release_dir/manifest.txt" || {
  echo "Release-bundle checksum does not match manifest.txt." >&2
  exit 78
}

echo "Transferring exactly three verified staging artifacts to $remote_target"
scp "${scp_options[@]}" \
  "$release_dir/compass-staging-amd64.oci.tar" \
  "$release_dir/compass-staging-release.tar.gz" \
  "$release_dir/manifest.txt" \
  "$remote_target"
