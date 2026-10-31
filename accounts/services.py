from django.utils import timezone
from .models import LoginHistory

def get_client_ip(request):
    """
    Safely extract client IP address from HTTP request headers.
    """
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR', '127.0.0.1')
    return ip

def log_login_attempt(user, username, ip_address, user_agent, status):
    """
    Log an authentication attempt to LoginHistory and ActivityLog.
    """
    history = LoginHistory.objects.create(
        user=user,
        username_attempted=username,
        ip_address=ip_address,
        user_agent=user_agent[:500] if user_agent else '',
        status=status,
    )
    return history
