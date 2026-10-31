from django.urls import path
from . import views

app_name = 'monitoring'

urlpatterns = [
    path('activity/', views.user_security_activity_view, name='user_activity'),
    path('admin/users/', views.admin_users_view, name='admin_users'),
    path('admin/files/', views.admin_files_view, name='admin_files'),
    path('admin/shares/', views.admin_shares_view, name='admin_shares'),
    path('admin/logs/', views.admin_security_logs_view, name='admin_logs'),
    path('admin/suspicious/', views.admin_suspicious_view, name='admin_suspicious'),
    path('admin/settings/', views.admin_settings_view, name='admin_settings'),
]
