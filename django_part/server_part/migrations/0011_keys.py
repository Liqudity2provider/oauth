# Generated by Django 4.1.2 on 2022-10-14 15:09

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('server_part', '0010_token_user'),
    ]

    operations = [
        migrations.CreateModel(
            name='Keys',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('public_key', models.CharField(max_length=500)),
                ('private_key', models.CharField(max_length=2000)),
                ('algorithm', models.CharField(max_length=50)),
                ('token', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='server_part.token')),
            ],
        ),
    ]