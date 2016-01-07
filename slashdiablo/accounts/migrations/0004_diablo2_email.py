# -*- coding: utf-8 -*-
# Generated by Django 1.9.1 on 2016-01-07 21:16
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0003_auto_20160107_2055'),
    ]

    operations = [
        migrations.AddField(
            model_name='diablo2',
            name='email',
            field=models.EmailField(blank=True, help_text='Diablo 2 registered email address', max_length=254, null=True),
        ),
    ]
