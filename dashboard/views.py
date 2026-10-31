from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required, user_passes_test
from django.db.models import Sum, Count
from django.utils import timezone
from django.contrib.auth import get_user_model

from filemanager.models import FileRecord
from sharing.models import FileShare, SharingLink
from monitoring.models import ActivityLog, SecurityEvent
from accounts.context_processors import get_lan_ip

User = get_user_model()

def format_bytes(bytes_val):
    if not bytes_val:
        return "0 KB"
    val = float(bytes_val)
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if val < 1024.0:
            return f"{val:.1f} {unit}"
        val /= 1024.0
    return f"{val:.1f} PB"

@login_required
def user_dashboard_view(request):
    user = request.user
    user_files = FileRecord.objects.filter(owner=user, is_deleted=False)

    # Real calculated statistics
    total_files = user_files.count()
    total_encrypted = user_files.filter(encryption_metadata__isnull=False).count()
    files_shared = FileShare.objects.filter(sender=user, is_revoked=False).count()
    files_received = FileShare.objects.filter(recipient=user, is_revoked=False, file_record__is_deleted=False).count()

    user_links = SharingLink.objects.filter(creator=user)
    now = timezone.now()
    active_links = sum(1 for link in user_links if link.is_valid()[0])
    expired_links = user_links.count() - active_links

    total_storage_bytes = user_files.aggregate(total=Sum('file_size'))['total'] or 0

    recent_files = user_files.order_by('-created_at')[:5]
    recent_activities = ActivityLog.objects.filter(user=user).order_by('-timestamp')[:6]
    security_events = SecurityEvent.objects.filter(user=user).order_by('-timestamp')[:4]

    context = {
        'total_files': total_files,
        'total_encrypted': total_encrypted,
        'files_shared': files_shared,
        'files_received': files_received,
        'active_links': active_links,
        'expired_links': expired_links,
        'storage_used_formatted': format_bytes(total_storage_bytes),
        'storage_used_bytes': total_storage_bytes,
        'recent_files': recent_files,
        'recent_activities': recent_activities,
        'security_events': security_events,
    }

    return render(request, 'dashboard/user_dashboard.html', context)


@user_passes_test(lambda u: u.is_authenticated and (u.is_admin or u.is_superuser))
def admin_dashboard_view(request):
    total_users = User.objects.count()
    active_users = User.objects.filter(is_suspended=False, is_active=True).count()
    suspended_users = User.objects.filter(is_suspended=True).count()

    all_files = FileRecord.objects.filter(is_deleted=False)
    total_files = all_files.count()
    total_encrypted = all_files.filter(encryption_metadata__isnull=False).count()
    total_storage = all_files.aggregate(total=Sum('file_size'))['total'] or 0

    total_shares = FileShare.objects.filter(is_revoked=False).count()
    all_links = SharingLink.objects.all()
    active_links = sum(1 for l in all_links if l.is_valid()[0])
    expired_links = all_links.count() - active_links

    security_alerts_count = SecurityEvent.objects.filter(is_reviewed=False).count()
    recent_alerts = SecurityEvent.objects.order_by('-timestamp')[:5]
    recent_activities = ActivityLog.objects.order_by('-timestamp')[:8]

    host_ip = get_lan_ip()
    port = request.get_port() or '8000'

    context = {
        'total_users': total_users,
        'active_users': active_users,
        'suspended_users': suspended_users,
        'total_files': total_files,
        'total_encrypted': total_encrypted,
        'total_storage_formatted': format_bytes(total_storage),
        'total_shares': total_shares,
        'active_links': active_links,
        'expired_links': expired_links,
        'security_alerts_count': security_alerts_count,
        'recent_alerts': recent_alerts,
        'recent_activities': recent_activities,
        'host_ip': host_ip,
        'port': port,
    }

    return render(request, 'dashboard/admin_dashboard.html', context)
