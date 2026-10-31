from django.contrib import admin
from .models import FileRecord, FileEncryptionMetadata, FileVersion

class FileEncryptionMetadataInline(admin.StackedInline):
    model = FileEncryptionMetadata
    readonly_fields = ('stored_filename', 'wrapped_dek', 'nonce', 'algorithm', 'key_wrap_algorithm', 'integrity_status', 'last_verified_at')
    can_delete = False
    extra = 0

class FileVersionInline(admin.TabularInline):
    model = FileVersion
    readonly_fields = ('version_number', 'file_size', 'sha256_hash', 'stored_filename', 'uploaded_by', 'created_at')
    extra = 0
    can_delete = False

@admin.register(FileRecord)
class FileRecordAdmin(admin.ModelAdmin):
    list_display = ('display_name', 'owner', 'file_type', 'file_size', 'current_version', 'is_deleted', 'created_at')
    list_filter = ('file_type', 'is_deleted', 'created_at')
    search_fields = ('display_name', 'original_filename', 'sha256_hash', 'owner__username')
    inlines = [FileEncryptionMetadataInline, FileVersionInline]
