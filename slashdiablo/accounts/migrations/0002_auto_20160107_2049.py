# -*- coding: utf-8 -*-
# Generated by Django 1.9.1 on 2016-01-07 20:49
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0001_initial'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='diablo2',
            options={'permissions': (('sync_all', 'Can resync all Diablo 2 account data'),)},
        ),
        migrations.AlterField(
            model_name='diablo2',
            name='commandgroups',
            field=models.IntegerField(default=1, help_text='Diablo 2 command groups (1 is Default)'),
        ),
    ]