from django.db import models
from django.utils import timezone
from datetime import date


class CertInfo(models.Model):
    OCSP = models.CharField(max_length=255, null=False)
    caIssuers = models.CharField(max_length=255, null=True)
    crlDistributionPoints = models.CharField(max_length=255, null=True)
    issuer_countryName = models.CharField(max_length=20)
    issuer_organizationName = models.CharField(max_length=255, null=True)
    issuer_organizationalUnitName = models.CharField(max_length=255, null=True)
    issuer_commonName = models.CharField(max_length=255, null=True)
    notAfter = models.DateTimeField(null=True)
    notBefore = models.DateTimeField(null=True)
    serialNumber = models.CharField(max_length=255, null=True)
    subject_businessCategory = models.CharField(max_length=255, null=True)
    subject_serialNumber = models.CharField(max_length=255, null=True)
    subject_streetAddress = models.CharField(max_length=255, null=True)
    subject_postalCode = models.CharField(max_length=255, null=True)
    subject_countryName = models.CharField(max_length=50)
    subject_stateOrProvinceName = models.CharField(max_length=255, null=True)
    subject_localityName = models.CharField(max_length=255, null=True)
    subject_organizationName = models.CharField(max_length=255, null=True)
    subject_commonName = models.CharField(max_length=255, null=True)
    version = models.CharField(max_length=5, null=True)
    subjectAltName = models.CharField(max_length=2000, null=True)
    expiry_date = models.DateField(null=True)
    created_at = models.DateTimeField(default=timezone.now())
    domain = models.CharField(null=True, max_length=255)
    ip = models.CharField(max_length=30, null=True)


class FileModel(models.Model):
    document = models.FileField(upload_to='documents/')
    uploaded_at = models.DateTimeField(default=timezone.now())
