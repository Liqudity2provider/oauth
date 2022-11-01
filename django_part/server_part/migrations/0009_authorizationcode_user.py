# Generated by Django 4.1.1 on 2022-09-21 14:55

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('server_part', '0008_alter_authorizationcode_code'),
    ]

    operations = [
        migrations.AddField(
            model_name='authorizationcode',
            name='user',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL),
        ),
    ]