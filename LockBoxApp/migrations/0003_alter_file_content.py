# Generated by Django 5.0.4 on 2024-05-13 14:15

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("LockBoxApp", "0002_file_shared_with"),
    ]

    operations = [
        migrations.AlterField(
            model_name="file",
            name="content",
            field=models.FileField(upload_to="files/%Y/%m/%d/"),
        ),
    ]
