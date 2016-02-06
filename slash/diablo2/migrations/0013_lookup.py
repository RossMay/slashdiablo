# -*- coding: utf-8 -*-
# Generated by Django 1.9.1 on 2016-02-06 00:47
from __future__ import unicode_literals

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('diablo2', '0012_auto_20160206_0021'),
    ]

    operations = [
        migrations.CreateModel(
            name='Lookup',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('type', models.CharField(help_text='Type of lookup', max_length=20)),
                ('target', models.CharField(help_text='Target of lookup', max_length=20)),
                ('query', models.CharField(help_text='User provided query', max_length=255)),
                ('parsed_query', models.CharField(help_text='Actual query run', max_length=255)),
                ('results', models.IntegerField(help_text='Number of results')),
                ('user', models.ForeignKey(help_text='User who ran the query', on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'Lookup Log',
            },
        ),
    ]