# Generated by Django 5.0 on 2024-04-02 10:08

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('NIDSApp', '0002_remove_uploadedfile_pcapng_file_and_more'),
    ]

    operations = [
        migrations.DeleteModel(
            name='UploadedFile',
        ),
    ]
