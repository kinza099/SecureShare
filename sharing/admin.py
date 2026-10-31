from django.contrib import admin
from .models import FileShare, SharingLink, FileDownloadAudit

@admin.register(FileShare)
class FileShareAdmin(admin.ModelAdmin):
    list_display = ('file_record', 'sender', 'recipient', 'permission', 'expires_at', 'is_revoked', 'created_at')
    list_filter = ('permission', 'is_revoked', 'created_at')
    search_fields = ('file_record__display_name', 'sender__username', 'recipient__username')

@admin.register(SharingLink)
class SharingLinkAdmin(admin.ModelAdmin):
    list_display = ('file_record', 'creator', 'is_password_protected', 'download_count', 'max_downloads', 'expires_at', 'is_revoked', 'created_at')
    list_filter = ('is_password_protected', 'is_revoked', 'created_at')
    search_fields = ('file_record__display_name', 'creator__username', 'token_hash')

@admin.register(FileDownloadAudit)
class FileDownloadAuditAdmin(admin.ModelAdmin):
    list_display = ('file_record', 'user', 'download_type', 'ip_address', 'status', 'timestamp')
    list_filter = ('download_type', 'status', 'timestamp')
    search_fields = ('file_record__display_name', 'user__username', 'ip_address')
