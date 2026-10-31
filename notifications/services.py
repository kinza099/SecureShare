from django.contrib.auth import get_user_model
from .models import Notification

User = get_user_model()

def create_notification(user, title, message, notification_type='GENERAL', link_url=''):
    """
    Dispatch an in-app notification to a user.
    """
    if not user:
        return None
    return Notification.objects.create(
        user=user,
        title=title,
        message=message,
        notification_type=notification_type,
        link_url=link_url
    )

def notify_admins(title, message, notification_type='SECURITY_ALERT'):
    """
    Send notification to all active administrators.
    """
    admins = User.objects.filter(is_admin=True, is_active=True)
    notifications = []
    for admin in admins:
        notifications.append(
            Notification(
                user=admin,
                title=title,
                message=message,
                notification_type=notification_type,
                link_url='/monitoring/admin/security-events/'
            )
        )
    if notifications:
        Notification.objects.bulk_create(notifications)
