#!/usr/bin/env python3
"""Build, package, and transfer the committed OCI staging release.

The implementation is intentionally Python-based so the same release
contract can be called from POSIX shells and PowerShell.  It never contacts
OCI, Cloudflare, or a container registry; Podman and scp are still explicit
operator-provided dependencies.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path
from typing import Iterable, Sequence


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
RELEASE_PATHS = (
    "compose.staging.yaml",
    "deploy/oci/bootstrap_vault_podman_secrets.sh",
    "deploy/compass-secret-env.sh",
    "deploy/oci/nginx/compass.conf",
    "deploy/oci/staging.env.example",
    "deploy/oci/vault-secret-map.example",
)
SUPPORTED_ARCHITECTURES = {"amd64", "arm64"}
SAFE_ARTIFACT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


class ReleaseError(Exception):
    """An actionable release validation or execution failure."""

    def __init__(self, message: str, exit_code: int = 78) -> None:
        super().__init__(message)
        self.exit_code = exit_code


def fail(message: str, exit_code: int = 78) -> None:
    raise ReleaseError(message, exit_code)


def require_command(name: str) -> None:
    if shutil.which(name) is None:
        fail(f"{name} is required.", 127)


def run_command(command: Sequence[str], *, cwd: Path = REPOSITORY_ROOT) -> None:
    try:
        subprocess.run(list(command), cwd=cwd, check=True)
    except FileNotFoundError:
        fail(f"Required command is not available: {command[0]}", 127)
    except subprocess.CalledProcessError as exc:
        fail(f"Command failed with exit code {exc.returncode}: {' '.join(command)}", exc.returncode or 1)


def git_output(arguments: Sequence[str]) -> str:
    try:
        completed = subprocess.run(
            ["git", "-C", str(REPOSITORY_ROOT), *arguments],
            check=True,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        fail("Git is required.", 127)
    except subprocess.CalledProcessError as exc:
        detail = exc.stderr.strip() or "Git command failed."
        fail(detail, exc.returncode or 1)
    return completed.stdout.strip()


def ensure_repository() -> None:
    require_command("git")
    try:
        root = git_output(["rev-parse", "--show-toplevel"])
    except ReleaseError:
        raise ReleaseError("The repository root could not be verified.", 78)
    if Path(root).resolve() != REPOSITORY_ROOT:
        fail("The release script is not running from the expected repository root.", 78)


def ensure_clean_worktree() -> None:
    if git_output(["status", "--porcelain", "--untracked-files=all"]):
        fail(
            "Refusing staging release from a dirty worktree. "
            "Commit the reviewed release first; uncommitted files are never staged.",
            78,
        )


def release_commit() -> str:
    release_ref = os.environ.get("COMPASS_RELEASE_REF", "HEAD").strip() or "HEAD"
    try:
        return git_output(["rev-parse", "--verify", f"{release_ref}^{{commit}}"])
    except ReleaseError:
        fail(f"Release ref is not a commit: {release_ref}", 64)
    raise AssertionError("unreachable")


def require_tracked(paths: Iterable[str], *, label: str) -> None:
    for path in paths:
        try:
            git_output(["ls-files", "--error-unmatch", "--", path])
        except ReleaseError:
            fail(f"Required {label} file is not tracked: {path}", 78)


def required_architecture() -> str:
    image_arch = os.environ.get("COMPASS_IMAGE_ARCH", "").strip().lower()
    if image_arch not in SUPPORTED_ARCHITECTURES:
        fail(
            "Set COMPASS_IMAGE_ARCH to one of: amd64, arm64. "
            "The release scripts do not assume a host architecture.",
            64,
        )
    return image_arch


def image_tag() -> str:
    tag = os.environ.get("COMPASS_IMAGE_TAG", "").strip() or os.environ.get("COMPASS_IMAGE_REF", "").strip()
    if not tag:
        fail("Set COMPASS_IMAGE_TAG or COMPASS_IMAGE_REF before building an OCI release.", 64)
    return tag


def absolute_outside_repository(raw_path: str, label: str) -> Path:
    path = Path(raw_path).expanduser()
    if not path.is_absolute():
        fail(f"Use an absolute {label} path.", 64)
    path = path.resolve()
    try:
        path.relative_to(REPOSITORY_ROOT)
    except ValueError:
        return path
    fail(f"The {label} must be outside the repository.", 64)
    raise AssertionError("unreachable")


def safe_extract(archive: tarfile.TarFile, destination: Path) -> None:
    destination = destination.resolve()
    for member in archive:
        member_name = Path(member.name)
        if member_name.is_absolute() or ".." in member_name.parts:
            fail(f"Unsafe path in Git archive: {member.name}", 78)
        target = (destination / member_name).resolve()
        if target != destination and destination not in target.parents:
            fail(f"Unsafe extraction target in Git archive: {member.name}", 78)
        archive.extract(member, destination)


def extract_git_archive(commit: str, destination: Path, paths: Sequence[str] = ()) -> None:
    command = ["git", "-C", str(REPOSITORY_ROOT), "archive", "--format=tar"]
    if paths:
        command.extend(["--prefix=compass-staging-release/", commit, "--", *paths])
    else:
        command.append(commit)

    try:
        process = subprocess.Popen(
            command,
            cwd=REPOSITORY_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except FileNotFoundError:
        fail("Git is required.", 127)
    assert process.stdout is not None
    assert process.stderr is not None
    try:
        with tarfile.open(fileobj=process.stdout, mode="r|") as archive:
            safe_extract(archive, destination)
    except (tarfile.TarError, OSError) as exc:
        if process.poll() is None:
            process.kill()
        process.wait()
        fail(f"Could not extract the committed Git archive: {exc}", 78)
    stderr = process.stderr.read().decode(errors="replace").strip()
    return_code = process.wait()
    if return_code:
        fail(stderr or "Git archive failed.", return_code)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_image(archive_path: Path, commit: str, image_arch: str, tag: str) -> str:
    require_command("podman")
    if archive_path.exists():
        fail(f"Refusing to overwrite an existing image archive: {archive_path}", 73)
    archive_path.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="compass-staging-build-") as context_name:
        context = Path(context_name)
        extract_git_archive(commit, context)
        run_command(
            [
                "podman",
                "build",
                "--arch",
                image_arch,
                "--pull=missing",
                "--tag",
                tag,
                "--file",
                str(context / "Containerfile"),
                str(context),
            ]
        )
        run_command(
            [
                "podman",
                "save",
                "--format",
                "oci-archive",
                "--output",
                str(archive_path),
                tag,
            ]
        )

    archive_path.chmod(0o600)
    image_sha256 = sha256(archive_path)
    print(f"image_sha256={image_sha256}")
    print(f"release_commit={commit}")
    print(f"image_arch={image_arch}")
    print(f"image_tag={tag}")
    return image_sha256


def build(arguments: Sequence[str]) -> int:
    if len(arguments) != 1:
        fail("Usage: build /path/outside/repository/compass-<arch>.oci.tar", 64)
    ensure_repository()
    ensure_clean_worktree()
    commit = release_commit()
    require_tracked(("Containerfile", "requirements.txt", "deploy/compass-secret-env.sh"), label="staging release")
    image_arch = required_architecture()
    build_image(
        absolute_outside_repository(arguments[0], "image archive"),
        commit,
        image_arch,
        image_tag(),
    )
    return 0


def ensure_empty_output_directory(raw_path: str) -> Path:
    output_dir = absolute_outside_repository(raw_path, "release output")
    if output_dir.exists():
        if not output_dir.is_dir():
            fail(f"Release output path is not a directory: {output_dir}", 73)
        if any(output_dir.iterdir()):
            fail(f"Refusing to overwrite a non-empty release directory: {output_dir}", 73)
    else:
        output_dir.mkdir(parents=True)
    return output_dir


def write_private(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8", newline="\n")
    path.chmod(0o600)


def bundle_contains_forbidden_path(path: str) -> bool:
    return any(
        token in path
        for token in (
            "/.env",
            "/.env.",
            ".sqlite",
            ".sqlite3",
            ".db",
            "/media/",
            "/protected_media/",
            "/backups/",
            "/output/",
            "/tmp/",
            "/.local/",
            "/.git/",
        )
    )


def package(arguments: Sequence[str]) -> int:
    if len(arguments) != 1:
        fail("Usage: package /path/outside/repository/compass-staging-release", 64)
    ensure_repository()
    ensure_clean_worktree()
    commit = release_commit()
    require_tracked(RELEASE_PATHS, label="release-bundle")
    image_arch = required_architecture()
    tag = image_tag()
    output_dir = ensure_empty_output_directory(arguments[0])

    image_archive_name = f"compass-staging-{image_arch}.oci.tar"
    image_archive = output_dir / image_archive_name
    bundle_archive_name = "compass-staging-release.tar.gz"
    bundle_archive = output_dir / bundle_archive_name
    manifest_path = output_dir / "manifest.txt"
    build_image(image_archive, commit, image_arch, tag)

    with tempfile.TemporaryDirectory(prefix="compass-staging-package-") as package_name:
        package_root = Path(package_name)
        extract_git_archive(commit, package_root, RELEASE_PATHS)
        bundle_manifest = package_root / "compass-staging-release" / "RELEASE-MANIFEST.txt"
        image_sha256 = sha256(image_archive)
        write_private(
            bundle_manifest,
            "".join(
                [
                    f"release_commit={commit}\n",
                    f"image_arch={image_arch}\n",
                    f"image_tag={tag}\n",
                    f"image_archive={image_archive_name}\n",
                    f"image_sha256={image_sha256}\n",
                    "bundle_paths:\n",
                    *[f" - {path}\n" for path in RELEASE_PATHS],
                    " - RELEASE-MANIFEST.txt\n",
                ]
            ),
        )

        with tarfile.open(bundle_archive, mode="w:gz") as bundle:
            bundle.add(
                package_root / "compass-staging-release",
                arcname="compass-staging-release",
                recursive=True,
            )

    with tarfile.open(bundle_archive, mode="r:gz") as bundle:
        for member in bundle.getmembers():
            if bundle_contains_forbidden_path(member.name):
                fail(f"Forbidden local-only path in release bundle: {member.name}", 78)

    bundle_sha256 = sha256(bundle_archive)
    write_private(
        manifest_path,
        "".join(
            [
                f"release_commit={commit}\n",
                f"image_arch={image_arch}\n",
                f"image_tag={tag}\n",
                f"image_archive={image_archive_name}\n",
                f"image_sha256={image_sha256}\n",
                f"release_bundle={bundle_archive_name}\n",
                f"release_bundle_sha256={bundle_sha256}\n",
                "transfer_scope=approved image archive, release bundle, and this manifest only\n",
            ]
        ),
    )
    image_archive.chmod(0o600)
    bundle_archive.chmod(0o600)
    print(f"Staging release package created: {output_dir}")
    print(f"Image SHA-256: {image_sha256}")
    print(f"Bundle SHA-256: {bundle_sha256}")
    return 0


def manifest_values(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        values.setdefault(key, value)
    return values


def safe_manifest_artifact(value: str, field: str) -> str:
    if not SAFE_ARTIFACT_NAME.fullmatch(value) or Path(value).name != value:
        fail(f"manifest.txt contains an unsafe {field}: {value}", 78)
    return value


def push(arguments: Sequence[str]) -> int:
    if not arguments or arguments[0] != "--execute" or len(arguments) < 3:
        fail(
            "Usage: push --execute /path/release-dir user@host:/remote/path [-- scp-options ...]",
            64,
        )
    release_dir = absolute_outside_repository(arguments[1], "release directory")
    remote_target = arguments[2]
    if ":" not in remote_target or any(character in remote_target for character in "\r\n"):
        fail("Remote target must use user@host:/path syntax.", 64)

    remainder = list(arguments[3:])
    if remainder:
        if remainder[0] != "--":
            fail("Additional scp options must follow --.", 64)
        scp_options = remainder[1:]
    else:
        scp_options = []

    manifest_path = release_dir / "manifest.txt"
    if not manifest_path.is_file():
        fail(f"Release artifact is missing: {manifest_path}", 78)
    values = manifest_values(manifest_path)
    image_archive_name = safe_manifest_artifact(values.get("image_archive", ""), "image_archive")
    bundle_archive_name = safe_manifest_artifact(values.get("release_bundle", ""), "release_bundle")
    image_archive = release_dir / image_archive_name
    bundle_archive = release_dir / bundle_archive_name
    for artifact in (image_archive, bundle_archive):
        if not artifact.is_file():
            fail(f"Release artifact is missing: {artifact}", 78)

    expected_image_sha256 = values.get("image_sha256", "")
    expected_bundle_sha256 = values.get("release_bundle_sha256", "")
    if sha256(image_archive) != expected_image_sha256:
        fail("Image checksum does not match manifest.txt.", 78)
    if sha256(bundle_archive) != expected_bundle_sha256:
        fail("Release-bundle checksum does not match manifest.txt.", 78)

    require_command("scp")
    print(f"Transferring exactly three verified staging artifacts to {remote_target}")
    run_command(
        [
            "scp",
            *scp_options,
            str(image_archive),
            str(bundle_archive),
            str(manifest_path),
            remote_target,
        ],
        cwd=REPOSITORY_ROOT,
    )
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)
    build_parser = subcommands.add_parser("build")
    build_parser.add_argument("archive_path")
    package_parser = subcommands.add_parser("package")
    package_parser.add_argument("output_dir")
    push_parser = subcommands.add_parser("push")
    push_parser.add_argument("--execute", action="store_true")
    push_parser.add_argument("release_dir")
    push_parser.add_argument("remote_target")
    push_parser.add_argument("scp_options", nargs=argparse.REMAINDER)
    options = parser.parse_args(argv)

    try:
        if options.command == "build":
            return build([options.archive_path])
        if options.command == "package":
            return package([options.output_dir])
        push_arguments = ["--execute" if options.execute else "--no-execute", options.release_dir, options.remote_target]
        if options.scp_options:
            # argparse consumes the conventional ``--`` separator before it
            # exposes REMAINDER; restore it for the strict push() contract.
            push_arguments.extend(["--", *options.scp_options])
        return push(push_arguments)
    except ReleaseError as exc:
        print(f"OCI_RELEASE_ERROR={exc}", file=sys.stderr)
        return exc.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
