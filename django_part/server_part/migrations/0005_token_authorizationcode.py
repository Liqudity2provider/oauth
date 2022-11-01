# Generated by Django 4.1.1 on 2022-09-20 18:29

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('server_part', '0004_alter_client_grant_type'),
    ]

    operations = [
        migrations.CreateModel(
            name='Token',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('scopes', models.TextField()),
                ('access_token', models.CharField(max_length=100, unique=True)),
                ('refresh_token', models.CharField(max_length=100, unique=True)),
                ('expires_at', models.DateTimeField()),
                ('client', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='server_part.client')),
            ],
        ),
        migrations.CreateModel(
            name='AuthorizationCode',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('scopes', models.TextField()),
                ('redirect_uri', models.TextField()),
                ('code', models.CharField(max_length=100, unique=True)),
                ('expires_at', models.DateTimeField()),
                ('challenge', models.CharField(max_length=128, null=True)),
                ('challenge_method', models.CharField(max_length=6, null=True)),
                ('nonce', models.CharField(max_length=128, null=True)),
                ('client', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='server_part.client')),
            ],
        ),
    ]
