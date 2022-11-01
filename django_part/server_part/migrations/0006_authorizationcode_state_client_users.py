# Generated by Django 4.1.1 on 2022-09-20 20:33

from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('server_part', '0005_token_authorizationcode'),
    ]

    operations = [
        migrations.AddField(
            model_name='authorizationcode',
            name='state',
            field=models.CharField(max_length=128, null=True),
        ),
        migrations.AddField(
            model_name='client',
            name='users',
            field=models.ManyToManyField(to=settings.AUTH_USER_MODEL),
        ),
    ]