# Generated by Django 4.2.16 on 2024-12-06 13:46

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('user', '0005_fileupload_profile_picture'),
    ]

    operations = [
        migrations.AlterField(
            model_name='profile',
            name='otp_secret',
            field=models.CharField(blank=True, max_length=12, null=True),
        ),
        migrations.AlterField(
            model_name='user',
            name='otp_secret',
            field=models.CharField(blank=True, max_length=12, null=True),
        ),
    ]
