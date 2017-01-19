from django.contrib import admin
from ssl_watcher.models import FileModel, CertInfo

class CertInfoAdmin(admin.ModelAdmin):
	name = CertInfo
	list_display = [field.name for field in CertInfo._meta.fields if field.name != "id"]


# Register your models here.
# admin.site.register(models.FileModel)
admin.site.register(CertInfo, CertInfoAdmin)

