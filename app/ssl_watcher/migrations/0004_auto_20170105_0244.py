# -*- coding: utf-8 -*-
# Generated by Django 1.10 on 2017-01-05 02:44
from __future__ import unicode_literals

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('ssl_watcher', '0003_auto_20170105_0158'),
    ]

    operations = [
        migrations.RenameField(
            model_name='certinfo',
            old_name='issuer_notAfter',
            new_name='notAfter',
        ),
        migrations.RenameField(
            model_name='certinfo',
            old_name='issuer_notBefore',
            new_name='notBefore',
        ),
    ]
