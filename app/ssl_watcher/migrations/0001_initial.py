# -*- coding: utf-8 -*-
# Generated by Django 1.10 on 2017-01-04 14:37
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='CertInfo',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('OCSP', models.CharField(max_length=255)),
                ('caIssuers', models.CharField(max_length=255)),
                ('crlDistributionPoints', models.CharField(max_length=255)),
                ('issuer_countryName', models.CharField(max_length=20)),
                ('issuer_organizationName', models.CharField(max_length=255)),
                ('issuer_organizaionUnitName', models.CharField(max_length=255)),
                ('issuer_commonName', models.CharField(max_length=255)),
                ('issuer_notAfter', models.DateTimeField()),
                ('issuer_notBefore', models.DateTimeField()),
                ('issuer_serialNumber', models.CharField(max_length=255)),
                ('subject_businessCategory', models.CharField(max_length=255)),
                ('subject_serialNumber', models.CharField(max_length=255)),
                ('subject_streetAddress', models.CharField(max_length=255)),
                ('subject_postalCode', models.CharField(max_length=255)),
                ('subject_countryName', models.CharField(max_length=50)),
                ('subject_stateOrProvinceName', models.CharField(max_length=255)),
                ('subject_localityName', models.CharField(max_length=255)),
                ('subject_organizationName', models.CharField(max_length=255)),
                ('subject_commonName', models.CharField(max_length=255)),
            ],
        ),
        migrations.CreateModel(
            name='FileModel',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('document', models.FileField(upload_to='documents/')),
                ('uploaded_at', models.DateTimeField(auto_now_add=True)),
            ],
        ),
    ]
