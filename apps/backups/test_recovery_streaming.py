import hashlib
import shutil
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from django.core.exceptions import ValidationError
from django.test import SimpleTestCase

from apps.backups.adapters import (
    BackupArchiveBuilder,
    BackupArchiveEncryptionAdapter,
    BackupStorageAdapter,
    LEGACY_FERNET_MAX_BYTES,
    _read_bounded,
)
from apps.backups.choices import BackupEnvelopeFormatChoices


class RecoveryStreamingTests(SimpleTestCase):
    def test_local_archive_copy_is_chunked_and_integrity_preserving(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.bin"
            destination = root / "destination.bin"
            source.write_bytes(b"a" * (3 * 1024 * 1024 + 17))

            BackupStorageAdapter()._atomic_local_copy(source, destination)

            self.assertEqual(destination.stat().st_size, source.stat().st_size)
            self.assertEqual(
                hashlib.sha256(destination.read_bytes()).hexdigest(),
                hashlib.sha256(source.read_bytes()).hexdigest(),
            )

    def test_archive_member_stream_is_verified_without_content_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "payload.bin"
            archive_path = root / "payload.tar"
            source.write_bytes(b"payload" * 400_000)
            expected_checksum = hashlib.sha256(source.read_bytes()).hexdigest()

            import tarfile

            builder = BackupArchiveBuilder()
            with archive_path.open("wb") as handle:
                with tarfile.open(fileobj=handle, mode="w") as archive:
                    builder._add_file(
                        archive,
                        "payload.bin",
                        source,
                        expected_size=source.stat().st_size,
                        expected_checksum=expected_checksum,
                    )

            with tarfile.open(archive_path, "r:") as archive:
                member = archive.getmember("payload.bin")
                self.assertEqual(member.size, source.stat().st_size)

    def test_new_envelope_uses_gpg_and_removes_plaintext_only_after_success(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plaintext = root / "archive.tar"
            encrypted = root / "archive.tar.gpg"
            decrypted = root / "decrypted.tar"
            plaintext.write_bytes(b"synthetic archive payload")

            key_row = SimpleNamespace(key_version="file-v1", secret_reference="FILE_KEY")

            def fake_gpg(command, *, input, stdout, stderr, check, shell):
                output = Path(command[command.index("--output") + 1])
                source = Path(command[-1])
                shutil.copyfile(source, output)
                return SimpleNamespace(returncode=0)

            with patch("apps.backups.adapters.EncryptionKeyVersion.objects.get", return_value=key_row), patch(
                "apps.backups.adapters.load_key_material", return_value=b"secret-passphrase"
            ), patch("apps.backups.adapters.shutil.which", return_value="gpg"), patch(
                "apps.backups.adapters.subprocess.run", side_effect=fake_gpg
            ) as run:
                adapter = BackupArchiveEncryptionAdapter()
                result = adapter.encrypt_archive(plaintext, encrypted)
                adapter.decrypt_archive(
                    encrypted,
                    decrypted,
                    key_version_reference="file-v1",
                    envelope_format=result.envelope_format,
                )

            self.assertEqual(result.envelope_format, BackupEnvelopeFormatChoices.GPG_SYMMETRIC_V1)
            self.assertFalse(plaintext.exists())
            self.assertEqual(decrypted.read_bytes(), b"synthetic archive payload")
            self.assertNotIn(b"secret-passphrase", run.call_args.args[0])
            self.assertEqual(run.call_args.kwargs["input"], b"secret-passphrase")

    def test_legacy_fernet_token_has_a_hard_read_limit(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "legacy.token"
            path.write_bytes(b"x" * (LEGACY_FERNET_MAX_BYTES + 1))
            with self.assertRaises(ValidationError):
                _read_bounded(path, LEGACY_FERNET_MAX_BYTES)
