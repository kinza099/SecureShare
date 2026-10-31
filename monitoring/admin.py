from django.contrib import admin
from .models import ActivityLog, SecurityEvent, ApplicationSetting

@admin.register(ActivityLog)
class ActivityLogAdmin(admin.ModelAdmin):
    list_display = ('event_type', 'user', 'ip_address', 'status', 'resource_id', 'timestamp')
    list_filter = ('event_type', 'status', 'timestamp')
    search_fields = ('user__username', 'ip_address', 'resource_id', 'description')
    readonly_fields = ('user', 'event_type', 'timestamp', 'ip_address', 'user_agent', 'resource_id', 'description', 'status')

@admin.register(SecurityEvent)
class SecurityEventAdmin(admin.ModelAdmin):
    list_display = ('rule_name', 'severity', 'user', 'ip_address', 'is_reviewed', 'timestamp')
    list_filter = ('severity', 'is_reviewed', 'timestamp')
    search_fields = ('rule_name', 'description', 'user__username', 'ip_address')

@admin.register(ApplicationSetting)
class ApplicationSettingAdmin(admin.ModelAdmin):
    list_display = ('key', 'value', 'updated_at')
    search_fields = ('key', 'description')
