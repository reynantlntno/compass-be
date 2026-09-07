#!/usr/bin/env bash
# Build the approved COMPASS image for the OCI staging VM and export it without
# contacting a container registry. The build always uses a committed Git
# snapshot, never the current filesystem tree.
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "Usage: $0 /path/outside/repository/compass-amd64.oci.tar" >&2
  exit 64
fi

archive_path=$1
case "$archive_path" in
  /*) ;;
  *) echo "Use an absolute archive path." >&2; exit 64 ;;
esac

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)
case "$archive_path" in
  "$repo_root"|"$repo_root"/*)
    echo "The image archive must be outside the repository." >&2
    exit 64
    ;;
esac

command -v git >/dev/null 2>&1 || { echo "Git is required." >&2; exit 127; }
git -C "$repo_root" rev-parse --show-toplevel >/dev/null 2>&1 || {
  echo "The repository root could not be verified." >&2
  exit 78
}

if [ -n "$(git -C "$repo_root" status --porcelain --untracked-files=all)" ]; then
  echo "Refusing staging build from a dirty worktree." >&2
  echo "Commit the reviewed release first; uncommitted files are never staged." >&2
  exit 78
fi

release_ref=${COMPASS_RELEASE_REF:-HEAD}
release_commit=$(git -C "$repo_root" rev-parse --verify "${release_ref}^{commit}") || {
  echo "Release ref is not a commit: $release_ref" >&2
  exit 64
}

for required_path in Containerfile requirements.txt deploy/compass-secret-env.sh; do
  git -C "$repo_root" ls-files --error-unmatch -- "$required_path" >/dev/null 2>&1 || {
    echo "Required staging release file is not tracked: $required_path" >&2
    exit 78
  }
done

image_arch=${COMPASS_IMAGE_ARCH:-amd64}
if [ "$image_arch" != "amd64" ]; then
  echo "The OCI staging artifact must be built for amd64." >&2
  exit 64
fi
image_tag=${COMPASS_IMAGE_TAG:-localhost/compass:staging-$image_arch}

command -v podman >/dev/null 2>&1 || { echo "Podman is required." >&2; exit 127; }
if [ -e "$archive_path" ]; then
  echo "Refusing to overwrite an existing image archive: $archive_path" >&2
  exit 73
fi
mkdir -p "$(dirname -- "$archive_path")"

build_context=$(mktemp -d /tmp/compass-staging-build.XXXXXX)
cleanup() {
  rm -rf "$build_context"
}
trap cleanup EXIT HUP INT TERM

git -C "$repo_root" archive --format=tar "$release_commit" \
  | tar -xf - -C "$build_context"

podman build --arch "$image_arch" --pull=missing --tag "$image_tag" \
  --file "$build_context/Containerfile" "$build_context"
podman save --format oci-archive --output "$archive_path" "$image_tag"
chmod 0600 "$archive_path"

if command -v sha256sum >/dev/null 2>&1; then
  sha256sum "$archive_path"
elif command -v shasum >/dev/null 2>&1; then
  shasum -a 256 "$archive_path"
else
  echo "Neither sha256sum nor shasum is available." >&2
  exit 127
fi
printf 'release_commit=%s\n' "$release_commit"
