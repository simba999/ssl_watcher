# -*- coding: utf-8 -*-
# Generated by Django 1.10 on 2017-01-07 22:27
from __future__ import unicode_literals

import datetime
from django.db import migrations, models
from django.utils.timezone import utc


class Migration(migrations.Migration):

    dependencies = [
        ('ssl_watcher', '0019_auto_20170107_0920'),
    ]

    operations = [
        migrations.DeleteModel(
            name='SubjectAltName',
        ),
        migrations.AddField(
            model_name='certinfo',
            name='domain',
            field=models.CharField(max_length=255, null=True),
        ),
        migrations.AddField(
            model_name='certinfo',
            name='ip',
            field=models.CharField(max_length=30, null=True),
        ),
        migrations.AlterField(
            model_name='certinfo',
            name='created_at',
            field=models.DateTimeField(default=datetime.datetime(2017, 1, 7, 22, 27, 27, 918478, tzinfo=utc)),
        ),
        migrations.AlterField(
            model_name='filemodel',
            name='uploaded_at',
            field=models.DateTimeField(default=datetime.datetime(2017, 1, 7, 22, 27, 27, 919255, tzinfo=utc)),
        ),
    ]
