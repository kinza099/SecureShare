from django.db import models
from django.conf import settings

class ActivityLog(models.Model):
    """
    Centralized immutable audit log for all security and operational actions.
    Never records sensitive secrets, passwords, or encryption keys.
    """
    EVENT_TYPES = [
        ('LOGIN_SUCCESS', 'Successful Login'),
        ('LOGIN_FAILED', 'Failed Login Attempt'),
        ('LOGOUT', 'User Logout'),
        ('REGISTRATION', 'User Registration'),
        ('PASSWORD_CHANGE', 'Password Changed'),
        ('FILE_UPLOAD', 'File Uploaded & Encrypted'),
        ('FILE_DOWNLOAD', 'File Decrypted & Downloaded'),
        ('FILE_DELETE', 'File Deleted'),
        ('FILE_PREVIEW', 'File Previewed'),
        ('FILE_SHARE', 'File Shared with User'),
        ('SHARE_REVOKE', 'Share Access Revoked'),
        ('LINK_CREATE', 'Sharing Link Generated'),
        ('LINK_REVOKE', 'Sharing Link Revoked'),
        ('LINK_DOWNLOAD', 'Sharing Link Downloaded'),
        ('INTEGRITY_VERIFY', 'File Integrity Verified'),
        ('INTEGRITY_FAIL', 'File Integrity Verification Failed'),
        ('UNAUTHORIZED_ACCESS', 'Unauthorized Resource Access Attempt'),
        ('SUSPICIOUS_ACTIVITY', 'Suspicious Activity Detected'),
        ('ADMIN_ACTION', 'Administrator Configuration Changed'),
    ]

    STATUS_CHOICES = [
        ('SUCCESS', 'Success'),
        ('FAILURE', 'Failure'),
        ('WARNING', 'Warning'),
        ('BLOCKED', 'Blocked'),
    ]

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name='activity_logs')
    event_type = models.CharField(max_length=50, choices=EVENT_TYPES)
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    resource_id = models.CharField(max_length=255, blank=True, help_text="Identifier of file, link, or subject target")
    description = models.TextField(blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='SUCCESS')

    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['event_type', 'timestamp']),
            models.Index(fields=['ip_address', 'timestamp']),
            models.Index(fields=['user', 'timestamp']),
        ]

    def __str__(self):
        user_repr = self.user.username if self.user else f"Anonymous ({self.ip_address})"
        return f"[{self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}] {self.event_type} by {user_repr} - {self.status}"


class SecurityEvent(models.Model):
    """
    High-priority security alert detected by rule-based monitoring.
    Displayed on Administrator Security Dashboard for review.
    """
    SEVERITY_CHOICES = [
        ('LOW', 'Low'),
        ('MEDIUM', 'Medium'),
        ('HIGH', 'High'),
        ('CRITICAL', 'Critical'),
    ]

    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default='MEDIUM')
    rule_name = models.CharField(max_length=100)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name='security_events')
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    description = models.TextField()
    is_reviewed = models.BooleanField(default=False)
    reviewed_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name='reviewed_security_events')
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f"[{self.severity}] {self.rule_name} - {self.timestamp.strftime('%Y-%m-%d %H:%M')}"


class ApplicationSetting(models.Model):
    """
    Dynamic application settings managed by Administrator.
    """
    key = models.CharField(max_length=100, unique=True)
    value = models.TextField()
    description = models.TextField(blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    @classmethod
    def get_setting(cls, key, default=None):
        try:
            return cls.objects.get(key=key).value
        except cls.DoesNotExist:
            return default

    def __str__(self):
        return f"{self.key}: {self.value}"
