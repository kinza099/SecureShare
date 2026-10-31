from .models import Notification

def notifications_context(request):
    """
    Context processor providing unread notifications and count for the header navbar badge.
    """
    if request.user.is_authenticated:
        unread_count = Notification.objects.filter(user=request.user, is_read=False).count()
        recent_notifications = Notification.objects.filter(user=request.user)[:5]
        return {
            'UNREAD_NOTIFICATIONS_COUNT': unread_count,
            'RECENT_NOTIFICATIONS': recent_notifications,
        }
    return {
        'UNREAD_NOTIFICATIONS_COUNT': 0,
        'RECENT_NOTIFICATIONS': [],
    }
