from django.db import models
from django.conf import settings

class Notification(models.Model):
    TYPE_CHOICES = [
        ('FILE_UPLOAD', 'File Uploaded'),
        ('FILE_ENCRYPTED', 'File Encrypted'),
        ('FILE_SHARED', 'File Shared with You'),
        ('FILE_DOWNLOADED', 'Your Shared File Was Downloaded'),
        ('LINK_CREATED', 'Sharing Link Created'),
        ('LINK_REVOKED', 'Sharing Link Revoked'),
        ('LINK_EXPIRED', 'Sharing Link Expired'),
        ('SECURITY_ALERT', 'Security Notification'),
        ('VERSION_UPLOADED', 'New File Version Uploaded'),
        ('GENERAL', 'System Notice'),
    ]

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='notifications')
    title = models.CharField(max_length=200)
    message = models.TextField()
    notification_type = models.CharField(max_length=50, choices=TYPE_CHOICES, default='GENERAL')
    link_url = models.CharField(max_length=255, blank=True)
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.title} -> {self.user.username} ({'Read' if self.is_read else 'Unread'})"
