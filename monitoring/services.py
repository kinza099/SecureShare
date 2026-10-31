from django.utils import timezone
from datetime import timedelta
from .models import ActivityLog, SecurityEvent

def get_client_ip(request):
    if not request:
        return '127.0.0.1'
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR', '127.0.0.1')

def log_activity(request=None, user=None, event_type='ACTION', resource_id='', description='', status='SUCCESS', ip_address=None):
    """
    Record an action into ActivityLog.
    """
    try:
        if request and not user and hasattr(request, 'user') and request.user.is_authenticated:
            user = request.user
        if not ip_address and request:
            ip_address = get_client_ip(request)
        user_agent = request.META.get('HTTP_USER_AGENT', '') if request else ''
        
        return ActivityLog.objects.create(
            user=user if (user and user.is_authenticated) else None,
            event_type=event_type,
            ip_address=ip_address or '127.0.0.1',
            user_agent=user_agent[:500],
            resource_id=str(resource_id),
            description=description,
            status=status,
        )
    except Exception as e:
        # Failsafe so auditing never crashes primary business transaction
        print(f"Error logging activity: {e}")
        return None

def trigger_security_alert(rule_name, description, severity='MEDIUM', user=None, ip_address=None, request=None):
    """
    Create a SecurityEvent alert for administrator review.
    """
    try:
        if request and not ip_address:
            ip_address = get_client_ip(request)
        if request and not user and hasattr(request, 'user') and request.user.is_authenticated:
            user = request.user

        event = SecurityEvent.objects.create(
            rule_name=rule_name,
            description=description,
            severity=severity,
            user=user if (user and user.is_authenticated) else None,
            ip_address=ip_address or '127.0.0.1',
        )

        # Notify active administrators
        from notifications.services import notify_admins
        notify_admins(
            title=f"Security Alert: {rule_name}",
            message=description,
            notification_type='SECURITY_ALERT'
        )
        return event
    except Exception as e:
        print(f"Error creating security alert: {e}")
        return None

def evaluate_failed_logins(username, ip_address):
    """
    Evaluate recent failed logins for this username or IP in the last 15 minutes.
    """
    since = timezone.now() - timedelta(minutes=15)
    recent_failures = ActivityLog.objects.filter(
        event_type='LOGIN_FAILED',
        timestamp__gte=since,
    )
    user_failures = recent_failures.filter(description__icontains=username).count()
    ip_failures = recent_failures.filter(ip_address=ip_address).count()

    if user_failures >= 5 or ip_failures >= 5:
        trigger_security_alert(
            rule_name='Multiple Failed Login Attempts',
            description=f"Detected {max(user_failures, ip_failures)} failed logins in 15 mins for account '{username}' from IP {ip_address}.",
            severity='HIGH',
            ip_address=ip_address,
        )
