from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import User, LoginHistory

@admin.register(User)
class CustomUserAdmin(UserAdmin):
    list_display = ('username', 'email', 'full_name', 'is_admin', 'is_suspended', 'failed_login_attempts', 'is_staff')
    list_filter = ('is_admin', 'is_suspended', 'is_staff', 'is_superuser')
    fieldsets = UserAdmin.fieldsets + (
        ('Security & RBAC Attributes', {
            'fields': ('full_name', 'is_admin', 'is_suspended', 'failed_login_attempts', 'lockout_until', 'last_login_ip', 'two_factor_enabled')
        }),
    )

@admin.register(LoginHistory)
class LoginHistoryAdmin(admin.ModelAdmin):
    list_display = ('username_attempted', 'ip_address', 'status', 'timestamp', 'user')
    list_filter = ('status', 'timestamp')
    search_fields = ('username_attempted', 'ip_address')
