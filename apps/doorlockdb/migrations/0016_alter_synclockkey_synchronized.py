# Generated by Django 4.2.13 on 2024-05-22 09:32

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("doorlockdb", "0015_remove_lock_token_alter_lock_certificate_and_more"),
    ]

    operations = [
        migrations.AlterField(
            model_name="synclockkeys",
            name="synchronized",
            field=models.BooleanField(default=False, null=True),
        ),
    ]