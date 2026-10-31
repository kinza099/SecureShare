"""
URL configuration for Secure File Sharing System.
"""
from django.contrib import admin
from django.urls import path, include
from django.shortcuts import redirect

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', lambda request: redirect('dashboard:user_dashboard') if request.user.is_authenticated else redirect('accounts:login'), name='root'),
    path('accounts/', include('accounts.urls', namespace='accounts')),
    path('dashboard/', include('dashboard.urls', namespace='dashboard')),
    path('files/', include('filemanager.urls', namespace='filemanager')),
    path('sharing/', include('sharing.urls', namespace='sharing')),
    path('monitoring/', include('monitoring.urls', namespace='monitoring')),
    path('notifications/', include('notifications.urls', namespace='notifications')),
]
