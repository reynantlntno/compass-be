# COMPASS disaster recovery runbook

## Scope and safety gate

This runbook describes an operator-led recovery rehearsal or a separately
authorized recovery. It never authorizes a restore into a shared, staging, or
production database or object-storage prefix. Use a disposable PostgreSQL 16
instance, a scratch object-storage prefix, and synthetic data unless an
incident commander has recorded a separate go/no-go authorization.

Do not run `pg_restore --clean`, reset a database, delete a bucket, rotate
keys, or change retention on shared infrastructure. Do not put credentials or
key material in command arguments, transcripts, tickets, or the portal.

## Verified disposable rehearsal

On 2026-09-07, a synthetic PostgreSQL 16 custom-format dump was created in a
temporary source container, restored into a separate temporary target
container with `pg_restore --no-owner --no-acl`, and verified by querying the
restored probe row. Both containers and the temporary archive were removed.
This validates the local restore mechanics only; it does not claim that a
production backup artifact or protected-media recovery has been rehearsed.

## Preconditions

Confirm all of the following before retrieving an artifact:

1. Select the latest `VERIFIED` backup whose manifest covers the requested
   component. Record only its job ID, artifact ID, size, checksum, envelope
   format, and key-version reference.
2. Confirm PostgreSQL 16 `pg_restore`, the standard `gpg` executable, and the
   approved storage CLI are available in the disposable operator environment.
3. Obtain the active or approved decrypt-only key version for
   `FILE_ENVELOPE_PLACEHOLDER` from its configured key source (`env`,
   `podman_secret`, or the approved Vault integration). The archive envelope
   key is separate from `FIELD_ENCRYPTION` keys.
4. Obtain `FIELD_ENCRYPTION`, `SECRET_KEY`, `AUDIT_HASH_SECRET`,
   `ACCOUNT_SECURITY_HASH_SECRET`, `ACCOUNT_ACTIVATION_TOKEN_SECRET`, and the
   disposable `DATABASE_URL` from the approved secret provider. Never copy
   these values into the backup manifest or evidence.
5. Confirm the scratch database, payload directory, and object-storage prefix
   are empty, private, and owned by the rehearsal operator.

If a key source, storage target, or disposable database is unavailable, stop
and record the recovery as unverified. A dry-run or metadata row is not proof
of restore execution.

## Retrieve and verify the envelope

Copy the selected object to a private scratch path using a chunked storage
client. Verify the recorded byte size and SHA-256 before decrypting. The
current standard envelope is `gpg_symmetric_v1`, produced with AES-256 and the
`FILE_ENVELOPE_PLACEHOLDER` material supplied through stdin:

```text
gpg --batch --quiet --no-options --homedir <private-gpg-home> \
  --pinentry-mode loopback --passphrase-fd 0 \
  --decrypt --output <scratch>/backup.tar \
  <scratch>/artifact.tar.gpg
```

Provide the passphrase through a protected stdin mechanism; never replace
`<private-gpg-home>` with a shared home directory. Verify the decrypted tar
checksum and the manifest hash recorded on the backup job. Historical
`fernet_v1` artifacts are legacy-only and are subject to the bounded legacy
limit in the backup adapter; do not use the legacy path for new backups.

## Disposable database recovery

Create an empty disposable PostgreSQL 16 database. Restore the custom-format
dump without destructive flags:

```text
pg_restore --no-owner --no-acl --dbname=<disposable-database> <scratch>/database.dump
python manage.py migrate --check
```

Run the application’s encryption/key checks against the disposable settings,
confirm expected schema and synthetic-row counts, and record PostgreSQL and
application versions. A successful `pg_restore` is not sufficient if the
field keys or configuration secrets are absent.

## Protected files and public media

Extract the tar into a private scratch directory with ownership restoration
disabled. Never extract directly into live media or protected storage. For
each `protected_files/<uuid>.bin` member, match the UUID to the restored
`ProtectedFile` row, stream it to the disposable protected-storage backend,
and verify both declared size and SHA-256. For each `public_media/<digest>.bin`
member, match the digest to the restored `BrandAsset.file` relative-name
hash, stream it to disposable media, and verify size and SHA-256.

Record counts and hashes, not payload contents. If a row has no matching
member or a member has no matching row, stop and report the exact component as
unrecovered.

## Retention and disposal

Check the configured backup retention class, object-storage versioning and
lifecycle policy, expiry timestamp, and any legal hold before declaring the
artifact retained. After a disposable rehearsal, stop and remove the scratch
database/container, scratch payload directory, temporary GPG home, and
scratch object prefix. Record cleanup success and any remaining provider-side
versions. Do not delete or alter shared/prod objects as part of this runbook.

## Evidence and status

Capture a redacted transcript containing the artifact identifiers, PostgreSQL
and GPG versions, source and decrypted checksums, manifest validation result,
`pg_restore` result, schema/data checks, payload hash checks, key/config
presence checks (never values), retention observations, and cleanup result.

Only after an actually authorized rehearsal has completed may the readiness
record claim real restore execution. Until then,
`real_backup_restore_execution` remains `NOT_CLAIMED`.
