import datetime
import uuid

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone


def backfill_api_sessions(apps, schema_editor):
    ApiToken = apps.get_model("account_security", "ApiToken")
    ApiSession = apps.get_model("account_security", "ApiSession")

    family_ids = (
        ApiToken.objects.order_by("family_id", "issued_at")
        .values_list("family_id", flat=True)
        .distinct()
    )
    max_age = datetime.timedelta(days=30)
    for family_id in family_ids:
        tokens = list(ApiToken.objects.filter(family_id=family_id).order_by("issued_at", "id"))
        if not tokens:
            continue
        first = tokens[0]
        started_at = first.issued_at
        refreshes = [
            token
            for token in tokens
            if token.token_type == "REFRESH"
        ]
        refresh_expiry = max(
            (token.expires_at for token in refreshes),
            default=started_at + max_age,
        )
        absolute_expires_at = min(refresh_expiry, started_at + max_age)
        now = django.utils.timezone.now()
        has_active_token = any(
            token.status == "ACTIVE" and token.expires_at > now
            for token in tokens
        )
        if absolute_expires_at <= now:
            status = "EXPIRED"
        elif has_active_token:
            status = "ACTIVE"
        else:
            status = "REVOKED"
        method = "migrated" if any(token.assurance_context for token in tokens) else "password"
        session = ApiSession.objects.create(
            id=family_id,
            user_id=first.user_id,
            status=status,
            device_summary="unknown device",
            network_class="unknown",
            authentication_method=method,
            security_stamp=first.security_stamp,
            started_at=started_at,
            last_activity_at=max(
                (token.last_used_at or token.issued_at for token in tokens),
                default=started_at,
            ),
            absolute_expires_at=absolute_expires_at,
            # Migrated rows intentionally receive no fresh sensitive assurance.
            last_otp_verified_at=None,
            revoked_at=now if status == "REVOKED" else None,
            revoked_reason="migrated_inactive_family" if status == "REVOKED" else None,
        )
        ApiToken.objects.filter(family_id=family_id).update(session_id=session.id)


class Migration(migrations.Migration):

    dependencies = [
        ("account_security", "0002_initial"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="ApiSession",
            fields=[
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("status", models.CharField(choices=[("ACTIVE", "Active"), ("REVOKED", "Revoked"), ("EXPIRED", "Expired")], default="ACTIVE", max_length=16)),
                ("device_summary", models.CharField(default="unknown device", max_length=120)),
                ("network_class", models.CharField(default="unknown", max_length=32)),
                ("authentication_method", models.CharField(choices=[("password", "Password"), ("otp", "OTP"), ("trusted_device", "Trusted device"), ("migrated", "Migrated")], default="password", max_length=24)),
                ("security_stamp", models.UUIDField()),
                ("started_at", models.DateTimeField(default=django.utils.timezone.now)),
                ("last_activity_at", models.DateTimeField(default=django.utils.timezone.now)),
                ("absolute_expires_at", models.DateTimeField()),
                ("last_otp_verified_at", models.DateTimeField(blank=True, null=True)),
                ("revoked_at", models.DateTimeField(blank=True, null=True)),
                ("revoked_reason", models.CharField(blank=True, max_length=100, null=True)),
                ("user", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="api_sessions", to=settings.AUTH_USER_MODEL)),
            ],
            options={
                "verbose_name": "API session",
                "verbose_name_plural": "API sessions",
            },
        ),
        migrations.CreateModel(
            name="StudentTwoFactorEnrollment",
            fields=[
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("enabled", models.BooleanField(default=False)),
                ("enabled_at", models.DateTimeField(blank=True, null=True)),
                ("disabled_at", models.DateTimeField(blank=True, null=True)),
                ("last_changed_at", models.DateTimeField(blank=True, null=True)),
                ("user", models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name="student_two_factor_enrollment", to=settings.AUTH_USER_MODEL)),
            ],
            options={
                "verbose_name": "student two-factor enrollment",
                "verbose_name_plural": "student two-factor enrollments",
            },
        ),
        migrations.AddField(
            model_name="trusteddevice",
            name="network_class",
            field=models.CharField(blank=True, default="unknown", max_length=32),
        ),
        migrations.AddField(
            model_name="apitoken",
            name="session",
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name="tokens", to="account_security.apisession"),
        ),
        migrations.AlterField(
            model_name="twostepchallenge",
            name="purpose",
            field=models.CharField(choices=[("login", "Login"), ("recovery", "Recovery"), ("activation", "Activation"), ("sensitive_action", "Sensitive Action"), ("two_factor_change", "Two-factor change")], max_length=30),
        ),
        migrations.AddIndex(
            model_name="apisession",
            index=models.Index(fields=["user", "status", "absolute_expires_at"], name="account_sec_user_id_7ad8fd_idx"),
        ),
        migrations.AddIndex(
            model_name="apisession",
            index=models.Index(fields=["status", "absolute_expires_at"], name="account_sec_status_08a5b2_idx"),
        ),
        migrations.RunPython(backfill_api_sessions, migrations.RunPython.noop),
    ]
