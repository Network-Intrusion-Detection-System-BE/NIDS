# Generated by Django 5.0 on 2024-04-22 11:52

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('NIDSApp', '0004_initial'),
    ]

    operations = [
        migrations.RenameField(
            model_name='networkdata',
            old_name='result',
            new_name='attack_type',
        ),
    ]