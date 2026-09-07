#!/usr/bin/env bash
# Build the approved amd64 image and create the allowlisted release bundle for
# transfer through an OCI Bastion-managed SSH session. This script never
# contacts OCI, Cloudflare, or a container registry.
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "Usage: $0 /path/outside/repository/compass-staging-release" >&2
  exit 64
fi

output_dir=$1
case "$output_dir" in
  /*) ;;
  *) echo "Use an absolute output directory." >&2; exit 64 ;;
esac

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)
case "$output_dir" in
  "$repo_root"|"$repo_root"/*)
    echo "The release output must be outside the repository." >&2
    exit 64
    ;;
esac

command -v git >/dev/null 2>&1 || { echo "Git is required." >&2; exit 127; }
git -C "$repo_root" rev-parse --show-toplevel >/dev/null 2>&1 || {
  echo "The repository root could not be verified." >&2
  exit 78
}

if [ -n "$(git -C "$repo_root" status --porcelain --untracked-files=all)" ]; then
  echo "Refusing to package a dirty worktree." >&2
  echo "Commit the reviewed release first; local-only and uncommitted files are never staged." >&2
  exit 78
fi

release_ref=${COMPASS_RELEASE_REF:-HEAD}
release_commit=$(git -C "$repo_root" rev-parse --verify "${release_ref}^{commit}") || {
  echo "Release ref is not a commit: $release_ref" >&2
  exit 64
}

release_paths=(
  compose.staging.yaml
  deploy/bootstrap_vault_podman_secrets.sh
  deploy/compass-secret-env.sh
  deploy/nginx/compass.conf
  deploy/staging.env.example
  deploy/vault-secret-map.example
)
for required_path in "${release_paths[@]}"; do
  git -C "$repo_root" ls-files --error-unmatch -- "$required_path" >/dev/null 2>&1 || {
    echo "Required release-bundle file is not tracked: $required_path" >&2
    exit 78
  }
done

if [ -e "$output_dir" ]; then
  [ -d "$output_dir" ] || {
    echo "Release output path is not a directory: $output_dir" >&2
    exit 73
  }
  [ -z "$(find "$output_dir" -mindepth 1 -print -quit)" ] || {
    echo "Refusing to overwrite a non-empty release directory: $output_dir" >&2
    exit 73
  }
else
  mkdir -p "$output_dir"
fi

image_tag=${COMPASS_IMAGE_TAG:-localhost/compass:staging-amd64}
image_archive="$output_dir/compass-staging-amd64.oci.tar"
bundle_archive="$output_dir/compass-staging-release.tar.gz"
manifest_path="$output_dir/manifest.txt"

COMPASS_IMAGE_ARCH=amd64 \
COMPASS_IMAGE_TAG="$image_tag" \
COMPASS_RELEASE_REF="$release_commit" \
  "$repo_root/scripts/oci/build_staging_image.sh" "$image_archive"

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

package_root=$(mktemp -d /tmp/compass-staging-package.XXXXXX)
cleanup() {
  rm -rf "$package_root"
}
trap cleanup EXIT HUP INT TERM

git -C "$repo_root" archive --format=tar \
  --prefix=compass-staging-release/ "$release_commit" -- "${release_paths[@]}" \
  | tar -xf - -C "$package_root"

image_sha256=$(checksum_value "$image_archive")
bundle_manifest="$package_root/compass-staging-release/RELEASE-MANIFEST.txt"
{
  printf 'release_commit=%s\n' "$release_commit"
  printf 'image_arch=amd64\n'
  printf 'image_tag=%s\n' "$image_tag"
  printf 'image_archive=compass-staging-amd64.oci.tar\n'
  printf 'image_sha256=%s\n' "$image_sha256"
  printf 'bundle_paths:\n'
  printf ' - %s\n' "${release_paths[@]}"
  printf ' - RELEASE-MANIFEST.txt\n'
} > "$bundle_manifest"
chmod 0600 "$bundle_manifest"

# Remove macOS provenance attributes from the temporary tree before creating
# an archive consumed by Oracle Linux.
if command -v xattr >/dev/null 2>&1; then
  xattr -rc "$package_root"
fi

# Prevent macOS extended-attribute sidecars (._ files) from entering the
# Linux-side release bundle.
COPYFILE_DISABLE=1 tar --no-xattrs -czf "$bundle_archive" -C "$package_root" compass-staging-release

while IFS= read -r bundle_path; do
  case "$bundle_path" in
    *'/.env'|*'/.env.'*|*.sqlite|*.sqlite3|*.db|*/media/*|*/protected_media/*|*/backups/*|*/output/*|*/tmp/*|*/.local/*|*/.git/*)
      echo "Forbidden local-only path in release bundle: $bundle_path" >&2
      exit 78
      ;;
  esac
done < <(tar -tzf "$bundle_archive")

bundle_sha256=$(checksum_value "$bundle_archive")
{
  printf 'release_commit=%s\n' "$release_commit"
  printf 'image_arch=amd64\n'
  printf 'image_tag=%s\n' "$image_tag"
  printf 'image_archive=compass-staging-amd64.oci.tar\n'
  printf 'image_sha256=%s\n' "$image_sha256"
  printf 'release_bundle=compass-staging-release.tar.gz\n'
  printf 'release_bundle_sha256=%s\n' "$bundle_sha256"
  printf 'transfer_scope=approved image archive, release bundle, and this manifest only\n'
} > "$manifest_path"
chmod 0600 "$manifest_path" "$image_archive" "$bundle_archive"

printf 'Staging release package created: %s\n' "$output_dir"
printf 'Image SHA-256: %s\n' "$image_sha256"
printf 'Bundle SHA-256: %s\n' "$bundle_sha256"
