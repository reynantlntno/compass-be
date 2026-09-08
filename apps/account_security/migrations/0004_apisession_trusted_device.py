import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("account_security", "0003_api_sessions_and_student_2fa"),
    ]

    operations = [
        migrations.AddField(
            model_name="apisession",
            name="trusted_device",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="api_sessions",
                to="account_security.trusteddevice",
            ),
        ),
    ]
