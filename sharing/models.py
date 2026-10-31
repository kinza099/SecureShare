import uuid
from django.db import models
from django.conf import settings
from django.utils import timezone
from filemanager.models import FileRecord

class FileShare(models.Model):
    """
    Direct user-to-user file sharing model.
    """
    PERMISSION_CHOICES = [
        ('VIEWER', 'Viewer (Preview Only)'),
        ('DOWNLOADER', 'Downloader (Preview and Download)'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    file_record = models.ForeignKey(FileRecord, on_delete=models.CASCADE, related_name='shares')
    sender = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='sent_shares')
    recipient = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='received_shares')
    permission = models.CharField(max_length=20, choices=PERMISSION_CHOICES, default='DOWNLOADER')
    message = models.TextField(blank=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    is_revoked = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']
        unique_together = ('file_record', 'recipient')

    def is_active(self):
        if self.is_revoked:
            return False
        if self.expires_at and timezone.now() > self.expires_at:
            return False
        return True

    def __str__(self):
        return f"{self.file_record.display_name} shared with {self.recipient.username} ({self.permission})"


class SharingLink(models.Model):
    """
    Time-bound, rate-limited, and password-protected link sharing.
    Stores only the SHA-256 hash of the public access token in the database.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    file_record = models.ForeignKey(FileRecord, on_delete=models.CASCADE, related_name='sharing_links')
    creator = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='created_links')
    token_hash = models.CharField(max_length=64, unique=True, db_index=True)
    is_password_protected = models.BooleanField(default=False)
    password_hash = models.CharField(max_length=255, blank=True)
    max_downloads = models.PositiveIntegerField(null=True, blank=True)
    download_count = models.PositiveIntegerField(default=0)
    expires_at = models.DateTimeField(null=True, blank=True)
    is_revoked = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def is_valid(self):
        """
        Check whether the link is currently valid for access.
        """
        if self.is_revoked:
            return False, "This sharing link has been revoked by the owner."
        if self.expires_at and timezone.now() > self.expires_at:
            return False, "This sharing link has expired."
        if self.max_downloads and self.download_count >= self.max_downloads:
            return False, "This sharing link has reached its maximum allowed downloads."
        return True, "Valid"

    def __str__(self):
        return f"Link for {self.file_record.display_name} by {self.creator.username}"


class FileDownloadAudit(models.Model):
    """
    Auditing records of all file downloads.
    """
    DOWNLOAD_TYPES = [
        ('OWNER', 'Owner Download'),
        ('SHARED_USER', 'Authorized Shared User'),
        ('SHARING_LINK', 'Public Link Access'),
    ]

    STATUS_CHOICES = [
        ('SUCCESS', 'Success'),
        ('INTEGRITY_FAILED', 'Integrity Check Failed'),
        ('DENIED', 'Access Denied'),
    ]

    file_record = models.ForeignKey(FileRecord, on_delete=models.CASCADE, related_name='download_audits')
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    sharing_link = models.ForeignKey(SharingLink, on_delete=models.SET_NULL, null=True, blank=True)
    download_type = models.CharField(max_length=20, choices=DOWNLOAD_TYPES)
    ip_address = models.GenericIPAddressField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='SUCCESS')
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-timestamp']
