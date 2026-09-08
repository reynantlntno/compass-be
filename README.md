# COMPASS

Django Backend

University of Camarines Norte (UCN)

Guidance and Counseling Office

## Local staging with Podman

The local-staging stack has platform-native wrappers for macOS/Linux and
Windows PowerShell. Both wrappers use the host architecture selected by
Podman and the native `podman-compose` provider for the stack's external
Podman secrets.

macOS/Linux:

```sh
./scripts/unix/local-staging.sh bootstrap
./scripts/unix/local-staging.sh up
./scripts/unix/local-staging.sh status
```

Windows PowerShell:

```powershell
.\scripts\windows\local-staging.ps1 -Action bootstrap
.\scripts\windows\local-staging.ps1 -Action up
.\scripts\windows\local-staging.ps1 -Action status
```

The generated `deploy/local-staging.env` is local-only and gitignored. Stop
the stack with the matching `down` action; do not use `down --volumes` unless
you intentionally want to remove the local database and storage volumes.
The checked-in local-staging example enables the supervised notification and
backup workers; set the worker gate to `False` only when intentionally pausing
queue processing.

Script layout: shared Python implementations are in `scripts/core`, Unix
entrypoints are in `scripts/unix`, Windows PowerShell entrypoints are in
`scripts/windows`, and OCI release wrappers are grouped under
`scripts/oci/unix` and `scripts/oci/windows`. OCI/Linux-only deployment assets
are in `deploy/oci`.

## OCI staging release

The OCI release implementation is shared by POSIX and PowerShell entrypoints.
Set the target architecture explicitly; no host architecture or artifact name
is assumed by the scripts:

```sh
COMPASS_IMAGE_ARCH=amd64 COMPASS_IMAGE_REF=localhost/compass:staging \
  ./scripts/oci/unix/package_staging_release.sh /tmp/compass-staging-release
# or: COMPASS_IMAGE_ARCH=arm64 COMPASS_IMAGE_REF=localhost/compass:staging \
#   ./scripts/oci/unix/package_staging_release.sh /tmp/compass-staging-release
```

The package records the architecture in `manifest.txt` and uses a dynamic image
archive name. Transfer only after reviewing the manifest:

```sh
./scripts/oci/unix/push_staging_release.sh --execute /tmp/compass-staging-release user@host:/path
```

PowerShell uses the matching `.ps1` files and the same `COMPASS_IMAGE_ARCH`
environment variable. Readiness checks require `COMPASS_HEALTHCHECK_URL` or
`COMPASS_API_BASE_URL`; they do not fall back to `localhost`.

```powershell
$env:COMPASS_IMAGE_ARCH = "amd64"
$env:COMPASS_IMAGE_REF = "localhost/compass:staging"
.\scripts\oci\windows\package_staging_release.ps1 C:\temp\compass-staging-release
```
