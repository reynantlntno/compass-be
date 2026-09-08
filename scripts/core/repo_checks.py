#!/usr/bin/env python3
"""Cross-platform, read-only repository policy checks."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path
from typing import Sequence


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


class CheckRunner:
    def __init__(self) -> None:
        self.failures = 0

    def fail(self, message: str) -> None:
        print(f"FAIL: {message}", file=sys.stderr)
        self.failures += 1

    def finish(self, label: str, exit_code: int = 1) -> int:
        if self.failures:
            print(f"{label} failed with {self.failures} issue(s).", file=sys.stderr)
            return exit_code
        print(f"{label} passed.")
        return 0


def read_repo_file(path: str) -> str:
    return (REPOSITORY_ROOT / path).read_text(encoding="utf-8")


def require_match(checks: CheckRunner, pattern: str, path: str, label: str) -> None:
    try:
        content = read_repo_file(path)
    except OSError:
        checks.fail(f"{path} is missing; expected {label}: {pattern}")
        return
    if pattern not in content:
        checks.fail(f"{path} is missing the {label}: {pattern}")


def require_absence(checks: CheckRunner, pattern: str, path: str, label: str) -> None:
    try:
        content = read_repo_file(path)
    except OSError:
        return
    if pattern in content:
        checks.fail(f"{path} contains a retired {label}: {pattern}")


def run_git(arguments: Sequence[str], *, check: bool = True) -> str:
    completed = subprocess.run(
        ["git", "-C", str(REPOSITORY_ROOT), *arguments],
        check=check,
        capture_output=True,
        text=True,
    )
    return completed.stdout


def git_path_is_ignored(path: str) -> bool:
    return (
        subprocess.run(
            ["git", "-C", str(REPOSITORY_ROOT), "check-ignore", "-q", "--", path],
            check=False,
        ).returncode
        == 0
    )


def verify_crawler_protection() -> int:
    checks = CheckRunner()
    contracts = (
        ('path("robots.txt", robots_txt, name="robots-txt")', "config/urls.py"),
        ("Disallow: /", "apps/system/http.py"),
        ("Disallow: /api/", "apps/system/http.py"),
        ("Disallow: /admin/", "apps/system/http.py"),
        ("Disallow: /docs/", "apps/system/http.py"),
        ("Disallow: /openapi.json", "apps/system/http.py"),
        ("apply_noindex_header(response)", "apps/common/api/middleware.py"),
        ('"X-Robots-Tag": NOINDEX_ROBOTS_TAG', "apps/common/api/errors.py"),
        ('"/api/v1/files/"', "apps/common/api/middleware.py"),
        (
            'add_header X-Robots-Tag "noindex, nofollow, noarchive" always;',
            "deploy/oci/nginx/compass.conf",
        ),
        ("signed branding-content path", "docs/DEPLOYMENT_CRAWLER_PROTECTION.md"),
    )
    for pattern, path in contracts:
        require_match(checks, pattern, path, "crawler-protection contract")

    try:
        nginx = read_repo_file("deploy/oci/nginx/compass.conf")
        robots = read_repo_file("apps/system/http.py")
    except OSError:
        nginx = robots = ""
    if re.search(r"^\s*autoindex\s+on", nginx, flags=re.MULTILINE):
        checks.fail("Nginx directory listing is enabled.")
    if re.search(r"^\s*Sitemap:", robots, flags=re.MULTILINE):
        checks.fail("robots.txt must not advertise a sitemap.")
    return checks.finish("Crawler-protection guard")


def verify_oci_staging_policy() -> int:
    checks = CheckRunner()
    stack_dir = REPOSITORY_ROOT / "infra/oci/staging"
    if not stack_dir.is_dir():
        print("OCI staging stack directory is missing.", file=sys.stderr)
        return 1

    allowed = {
        "oci_core_vcn",
        "oci_core_internet_gateway",
        "oci_core_service_gateway",
        "oci_core_route_table",
        "oci_core_security_list",
        "oci_core_subnet",
        "oci_core_network_security_group",
        "oci_core_network_security_group_security_rule",
        "oci_core_instance",
        "oci_core_volume",
        "oci_core_volume_attachment",
        "oci_load_balancer_load_balancer",
        "oci_load_balancer_backend_set",
        "oci_load_balancer_backend",
        "oci_load_balancer_listener",
        "oci_objectstorage_bucket",
        "oci_kms_vault",
        "oci_kms_key",
        "oci_bastion_bastion",
    }
    terraform = "\n".join(path.read_text(encoding="utf-8") for path in sorted(stack_dir.glob("*.tf")))
    resource_types = sorted(set(re.findall(r'resource\s+"(oci_[a-z0-9_]+)', terraform)))
    for resource_type in resource_types:
        if resource_type not in allowed:
            print(f"Unexpected OCI resource family in source: {resource_type}", file=sys.stderr)
            checks.failures += 1

    if re.search(
        r"oci_(psql|redis|database|core_nat_gateway|artifacts_|containerengine_|functions_|network_load_balancer|load_balancer_certificate)",
        terraform,
    ):
        print(
            "A disallowed managed, NAT, registry, or load-balancer certificate resource is present.",
            file=sys.stderr,
        )
        checks.failures += 1

    instance_count = len(re.findall(r'resource\s+"oci_core_instance"', terraform))
    if instance_count != 1:
        print(f"Expected exactly one Compute instance resource; found {instance_count}.", file=sys.stderr)
        checks.failures += 1

    try:
        variables = read_repo_file("infra/oci/staging/variables.tf")
        main = read_repo_file("infra/oci/staging/main.tf")
    except OSError:
        variables = main = ""
    if not re.search(r'default\s*=\s*"VM\.Standard\.E5\.Flex"', variables):
        print("The stack is not pinned to VM.Standard.E5.Flex.", file=sys.stderr)
        checks.failures += 1
    if not (
        re.search(r'protocol\s*=\s*"HTTP"', main)
        and re.search(r"ssl_configuration\s*\{", main)
        and re.search(r"certificate_ids\s*=\s*\[var\.origin_certificate_id\]", main)
    ):
        print("The stack is missing the OCI HTTPS listener (HTTP protocol with SSL configuration).", file=sys.stderr)
        checks.failures += 1
    if not re.search(r"port\s*=\s*443", main):
        print("The stack is missing the HTTPS listener on port 443.", file=sys.stderr)
        checks.failures += 1
    if re.search(r"port\s*=\s*80\s*$", terraform, flags=re.MULTILINE):
        print("The stack must not expose an HTTP listener.", file=sys.stderr)
        checks.failures += 1
    if not re.search(r"minimum_bandwidth_in_mbps\s*=\s*10", main):
        print("The LB minimum bandwidth is not 10 Mbps.", file=sys.stderr)
        checks.failures += 1

    if checks.failures:
        return 1
    print("OCI staging resource-policy check passed. Review the Resource Manager plan before apply.")
    return 0


def verify_staging_release_policy() -> int:
    checks = CheckRunner()

    dockerignore = (REPOSITORY_ROOT / ".dockerignore").read_text(encoding="utf-8").replace("\r", "")
    ignored_paths = (
        ".local/",
        "backups/",
        "media/",
        "protected_media/",
        "private_media/",
        "output/",
        "tmp/",
        "staticfiles/",
        "static_collected/",
        "docs/",
        "infra/",
        "scripts/",
        "tests/",
        "**/tests/",
        "compose*.yaml",
        "deploy/*",
        "!deploy/compass-secret-env.sh",
        "*.pem",
        "*.key",
        "*.p12",
        "*.pfx",
        "*.crt",
        "*.csr",
        "*.tfstate",
        "*.tfstate.*",
        ".env*",
    )
    for path in ignored_paths:
        if path not in dockerignore.splitlines():
            checks.fail(f".dockerignore is missing: {path}")

    required_paths = (
        "Containerfile",
        "compose.staging.yaml",
        "deploy/oci/bootstrap_vault_podman_secrets.sh",
        "deploy/compass-secret-env.sh",
        "deploy/oci/nginx/compass.conf",
        "deploy/oci/staging.env.example",
        "deploy/oci/vault-secret-map.example",
        "static/images/ucn_cnsc_logo.png",
    )
    for path in required_paths:
        if not (REPOSITORY_ROOT / path).is_file():
            checks.fail(f"Required file is missing: {path}")

    try:
        if git_path_is_ignored("deploy/compass-secret-env.sh"):
            checks.fail("The runtime secret wrapper is ignored by Git.")
        if git_path_is_ignored("static/images/ucn_cnsc_logo.png"):
            checks.fail("The new UCN/CNSC logo is ignored by Git.")
    except OSError as exc:
        checks.fail(f"Could not run Git policy checks: {exc}")

    tracked_local_only = 0
    tracked = run_git(["ls-files", "-z"]).split("\0")
    local_prefixes = (
        ".local/",
        "backups/",
        "media/",
        "protected_media/",
        "private_media/",
        "output/",
        "tmp/",
        "staticfiles/",
        "static_collected/",
    )
    for path in tracked:
        if path and path.startswith(local_prefixes):
            tracked_local_only += 1
    if tracked_local_only:
        print(
            f"NOTICE: {tracked_local_only} pre-existing local/review artifact(s) remain tracked but are excluded from staging.",
            file=sys.stderr,
        )

    compose_staging = read_repo_file("compose.staging.yaml")
    if re.search(r"^\s*build:", compose_staging, flags=re.MULTILINE):
        checks.fail("compose.staging.yaml must use an image, not a local build.")
    if re.search(r"^\s{2}(minio|mailpit):", compose_staging, flags=re.MULTILINE | re.IGNORECASE):
        checks.fail("compose.staging.yaml contains a local-only MinIO/Mailpit service.")

    release_source = read_repo_file("scripts/core/release.py")
    if '"archive", "--format=tar"' not in release_source:
        checks.fail("The image build script does not use a committed Git archive.")
    if '"status", "--porcelain", "--untracked-files=all"' not in release_source:
        checks.fail("The image build script lacks the dirty-worktree guard.")
    if "RELEASE_PATHS" not in release_source or "extract_git_archive(commit, package_root, RELEASE_PATHS)" not in release_source:
        checks.fail("The release package script does not use an explicit Git allowlist.")
    if '"scp"' not in release_source or '"--execute"' not in release_source:
        checks.fail("The staging transfer script lacks explicit scp execution gating.")
    if re.search(r"staging-amd64|image_arch=amd64|COMPASS_IMAGE_ARCH=amd64", release_source):
        checks.fail("OCI release scripts contain a hardcoded amd64 artifact or architecture.")

    urls = read_repo_file("config/urls.py")
    if 'path("api/v1/", api_v1.urls)' not in urls:
        checks.fail("config/urls.py does not expose the canonical API root.")
    if re.search(r"include\(|TemplateView|render\(", urls):
        checks.fail("config/urls.py contains a server-rendered/MVT root route.")

    governance_settings = (
        "ECOUNSELING_JOIN_WINDOW_BEFORE_MINUTES",
        "ECOUNSELING_JOIN_WINDOW_AFTER_MINUTES",
        "ECOUNSELING_DAILY_MEETING_TOKEN_TTL_SECONDS",
        "ECOUNSELING_RECORDING_ENABLED",
        "ECOUNSELING_RECORDING_WORKER_ENABLED",
        "ECOUNSELING_RECORDING_AUDIO_VIDEO_ENABLED",
        "ECOUNSELING_RECORDING_TRANSCRIPTION_ENABLED",
        "ECOUNSELING_RECORDING_TRANSCRIPTION_WORKER_ENABLED",
        "ECOUNSELING_RECORDING_MAX_FILE_SIZE_BYTES",
        "ECOUNSELING_RECORDING_TRANSCRIPTION_MAX_FILE_SIZE_BYTES",
    )
    for setting in governance_settings:
        for path in ("compose.staging.yaml", "deploy/oci/staging.env.example", ".env.example"):
            require_absence(checks, setting, path, "API-only deployment setting")
        if (REPOSITORY_ROOT / ".env").is_file():
            require_absence(checks, setting, ".env", "API-only deployment setting")

    deployment_settings = (
        "MAINTENANCE_ENFORCEMENT_ENABLED",
        "DOCUMENT_PDF_RENDERER_ENABLED",
        "DOCUMENT_PDF_RENDERER_TIMEOUT_MS",
        "ACCOUNT_SECURITY_CAPTCHA_TIMEOUT_SECONDS",
        "EMAIL_TIMEOUT",
        "NOTIFICATION_WORKER_ENABLED",
        "NOTIFICATION_WORKER_INTERVAL_SECONDS",
        "NOTIFICATION_WORKER_BATCH_SIZE",
        "NOTIFICATION_WORKER_LOCK_TIMEOUT_SECONDS",
        "BACKUP_WORKER_POLL_INTERVAL_SECONDS",
        "REPORT_SYNC_MAX_OUTPUT_BYTES",
        "REPORT_SYNC_MAX_WORK_UNITS",
        "REPORT_ASYNC_AFTER_WORK_UNITS",
        "REPORT_RUN_TIMEOUT_SECONDS",
        "REPORT_EXPORT_MAX_OUTPUT_BYTES",
        "PROTECTED_STORAGE_MAX_FILE_SIZE_BYTES",
    )
    for setting in deployment_settings:
        for path in ("compose.staging.yaml", "deploy/oci/staging.env.example", ".env.example"):
            require_match(checks, setting, path, "API-only deployment contract")

    # Every runnable stack declares the notification worker service. Keep the
    # copied examples and their Compose defaults aligned so a fresh bootstrap
    # does not silently start an idle worker or a failing backup worker.
    for path in (".env.example", "deploy/local-staging.env.example", "deploy/oci/staging.env.example"):
        require_match(
            checks,
            "NOTIFICATION_WORKER_ENABLED=True",
            path,
            "enabled supervised notification-worker example",
        )
    require_match(
        checks,
        "BACKUP_WORKER_ENABLED=True",
        ".env.example",
        "enabled supervised backup-worker example",
    )
    for path in ("compose.override.yaml", "compose.local-staging.yaml", "compose.staging.yaml"):
        require_absence(
            checks,
            "NOTIFICATION_WORKER_ENABLED: ${NOTIFICATION_WORKER_ENABLED:-False}",
            path,
            "disabled notification-worker Compose default",
        )

    retired_settings = (
        "ECOUNSELING_JOIN_DENIAL_RATE_LIMIT_COUNT",
        "ECOUNSELING_JOIN_DENIAL_RATE_LIMIT_WINDOW_SECONDS",
        "COMPASS_APPLICATION_BASE_URL",
        "COMPASS_ACTIVE_INSTITUTION_NAME",
        "COMPASS_ACTIVE_OFFICE_NAME",
        "student-activation-token-secret",
    )
    for setting in retired_settings:
        for path in ("compose.staging.yaml", "deploy/oci/staging.env.example", ".env.example"):
            require_absence(checks, setting, path, "retired deployment setting")
        if (REPOSITORY_ROOT / ".env").is_file():
            require_absence(checks, setting, ".env", "retired deployment setting")

    require_match(
        checks,
        'ALLOWED_HOSTS: "${ALLOWED_HOSTS:-staging-api.compass-gco.com}',
        "compose.staging.yaml",
        "API-only deployment contract",
    )
    require_match(
        checks,
        "COMPASS_API_BASE_URL: ${COMPASS_API_BASE_URL:-https://staging-api.compass-gco.com}",
        "compose.staging.yaml",
        "API-only deployment contract",
    )
    require_match(checks, "CORS_ALLOWED_ORIGINS=https://staging.compass-gco.com", "deploy/oci/staging.env.example", "API-only deployment contract")
    require_match(checks, "COMPASS_API_BASE_URL=https://staging-api.compass-gco.com", "deploy/oci/staging.env.example", "API-only deployment contract")
    require_match(checks, "COMPASS_CLIENT_BASE_URL=https://staging.compass-gco.com", "deploy/oci/staging.env.example", "API-only deployment contract")

    if checks.failures:
        return checks.finish("Staging release policy", 78)
    print("Staging release policy passed.")
    print("Local runtime data is excluded; release packaging remains committed-release only.")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("check", choices=("crawler", "oci", "staging-release"))
    options = parser.parse_args(argv)
    if options.check == "crawler":
        return verify_crawler_protection()
    if options.check == "oci":
        return verify_oci_staging_policy()
    return verify_staging_release_policy()


if __name__ == "__main__":
    raise SystemExit(main())
