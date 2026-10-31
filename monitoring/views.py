from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib import messages
from django.http import JsonResponse
from django.db.models import Sum, Count
from django.contrib.auth import get_user_model
from django.conf import settings

from .models import ActivityLog, SecurityEvent, ApplicationSetting
from filemanager.models import FileRecord
from sharing.models import SharingLink, FileShare
from accounts.context_processors import get_lan_ip

User = get_user_model()

def is_admin_user(user):
    return user.is_authenticated and (user.is_admin or user.is_superuser)

@login_required
def user_security_activity_view(request):
    """
    Shows personal security and file activity history for current user.
    """
    logs = ActivityLog.objects.filter(user=request.user).order_by('-timestamp')[:100]
    return render(request, 'monitoring/security_activity.html', {'logs': logs})


# ----------------- ADMINISTRATOR VIEWS -----------------

@user_passes_test(is_admin_user)
def admin_users_view(request):
    """
    Admin user management: view, activate, suspend, or toggle admin role.
    """
    query = request.GET.get('q', '').strip()
    users = User.objects.all().order_by('-date_joined')

    if query:
        users = users.filter(username__icontains=query) | users.filter(email__icontains=query)

    if request.method == 'POST':
        action = request.POST.get('action')
        target_user_id = request.POST.get('user_id')
        target_user = get_object_or_404(User, pk=target_user_id)

        if target_user == request.user and action == 'toggle_suspend':
            messages.error(request, "You cannot suspend your own account.")
        elif action == 'toggle_suspend':
            target_user.is_suspended = not target_user.is_suspended
            target_user.save(update_fields=['is_suspended'])
            status_str = "suspended" if target_user.is_suspended else "activated"
            messages.success(request, f"User {target_user.username} has been {status_str}.")
        elif action == 'toggle_admin':
            target_user.is_admin = not target_user.is_admin
            target_user.save(update_fields=['is_admin'])
            role_str = "Administrator" if target_user.is_admin else "Standard User"
            messages.success(request, f"User {target_user.username} is now {role_str}.")
        elif action == 'reset_lockout':
            target_user.reset_failed_attempts()
            messages.success(request, f"Lockout cleared for {target_user.username}.")

        return redirect('monitoring:admin_users')

    return render(request, 'monitoring/admin_users.html', {'users': users, 'query': query})


@user_passes_test(is_admin_user)
def admin_files_view(request):
    """
    File statistics and metadata monitor.
    NOTE: In strict compliance with zero-trust SSDD principles,
    administrators can view metadata but cannot decrypt users' private files.
    """
    files = FileRecord.objects.filter(is_deleted=False).select_related('owner', 'encryption_metadata').order_by('-created_at')
    total_storage = files.aggregate(total=Sum('file_size'))['total'] or 0

    return render(request, 'monitoring/admin_files.html', {
        'files': files,
        'total_storage': total_storage,
    })


@user_passes_test(is_admin_user)
def admin_shares_view(request):
    """
    System-wide monitoring of sharing activities and links.
    """
    links = SharingLink.objects.all().select_related('creator', 'file_record').order_by('-created_at')
    shares = FileShare.objects.all().select_related('sender', 'recipient', 'file_record').order_by('-created_at')

    return render(request, 'monitoring/admin_shares.html', {
        'links': links,
        'shares': shares,
    })


@user_passes_test(is_admin_user)
def admin_security_logs_view(request):
    """
    Centralized searchable and filterable activity audit logs.
    """
    logs = ActivityLog.objects.all().select_related('user').order_by('-timestamp')

    event_type = request.GET.get('event_type')
    status_filter = request.GET.get('status')
    user_query = request.GET.get('user')

    if event_type:
        logs = logs.filter(event_type=event_type)
    if status_filter:
        logs = logs.filter(status=status_filter)
    if user_query:
        logs = logs.filter(user__username__icontains=user_query)

    logs = logs[:200]

    return render(request, 'monitoring/admin_security_logs.html', {
        'logs': logs,
        'event_types': ActivityLog.EVENT_TYPES,
        'selected_event': event_type,
        'selected_status': status_filter,
    })


@user_passes_test(is_admin_user)
def admin_suspicious_view(request):
    """
    Rule-based security events review queue.
    """
    if request.method == 'POST' and 'review_event' in request.POST:
        event_id = request.POST.get('event_id')
        event = get_object_or_404(SecurityEvent, pk=event_id)
        event.is_reviewed = True
        event.reviewed_by = request.user
        event.save(update_fields=['is_reviewed', 'reviewed_by'])
        messages.success(request, f"Security event #{event.id} marked as reviewed.")
        return redirect('monitoring:admin_suspicious')

    events = SecurityEvent.objects.all().select_related('user', 'reviewed_by').order_by('-timestamp')
    return render(request, 'monitoring/admin_suspicious.html', {'events': events})


@user_passes_test(is_admin_user)
def admin_settings_view(request):
    """
    Configuration monitor for allowed extensions, upload size limits, and LAN settings.
    """
    host_ip = get_lan_ip()
    port = request.get_port() or '8000'

    return render(request, 'monitoring/admin_settings.html', {
        'host_ip': host_ip,
        'port': port,
        'allowed_extensions': getattr(settings, 'ALLOWED_FILE_EXTENSIONS', []),
        'max_upload_size_mb': getattr(settings, 'MAX_UPLOAD_SIZE_MB', 50),
        'session_timeout_sec': getattr(settings, 'SESSION_COOKIE_AGE', 1800),
        'encryption_algorithm': 'AES-256-GCM',
        'key_wrap_standard': 'NIST SP 800-38F',
        'hasher': 'Argon2id',
    })
