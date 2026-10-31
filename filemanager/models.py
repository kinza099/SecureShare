import uuid
from django.db import models
from django.conf import settings

class FileRecord(models.Model):
    """
    Metadata representation of an encrypted file stored in private storage.
    File contents are never stored directly in MySQL.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='files')
    display_name = models.CharField(max_length=255)
    original_filename = models.CharField(max_length=255)
    file_type = models.CharField(max_length=20)
    file_size = models.BigIntegerField(help_text="Original unencrypted file size in bytes")
    sha256_hash = models.CharField(max_length=64, db_index=True)
    current_version = models.PositiveIntegerField(default=1)
    is_deleted = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['owner', 'is_deleted']),
            models.Index(fields=['owner', 'sha256_hash']),
        ]

    def __str__(self):
        return f"{self.display_name} ({self.file_type.upper()}) - {self.owner.username}"

    @property
    def formatted_size(self):
        size = self.file_size
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} TB"


class FileEncryptionMetadata(models.Model):
    """
    Symmetric encryption parameters for a file.
    Raw DEK is NEVER stored; only the Master-KEK-wrapped DEK is saved.
    """
    INTEGRITY_CHOICES = [
        ('VERIFIED', 'Integrity Verified'),
        ('FAILED', 'Integrity Failed'),
        ('PENDING', 'Verification Pending'),
    ]

    file_record = models.OneToOneField(FileRecord, on_delete=models.CASCADE, related_name='encryption_metadata')
    stored_filename = models.CharField(max_length=255, unique=True, help_text="Encrypted filename in private_storage")
    wrapped_dek = models.TextField(help_text="Hex-encoded DEK wrapped with Master KEK")
    nonce = models.CharField(max_length=64, help_text="Hex-encoded 96-bit AES-GCM nonce")
    algorithm = models.CharField(max_length=50, default='AES-256-GCM')
    key_wrap_algorithm = models.CharField(max_length=50, default='NIST-SP-800-38F-KW')
    integrity_status = models.CharField(max_length=20, choices=INTEGRITY_CHOICES, default='VERIFIED')
    last_verified_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"EncMetadata for {self.file_record.display_name} ({self.algorithm})"


class FileVersion(models.Model):
    """
    Maintains historical versions of a file with distinct keys and ciphertext.
    """
    file_record = models.ForeignKey(FileRecord, on_delete=models.CASCADE, related_name='versions')
    version_number = models.PositiveIntegerField()
    stored_filename = models.CharField(max_length=255)
    file_size = models.BigIntegerField()
    sha256_hash = models.CharField(max_length=64)
    wrapped_dek = models.TextField()
    nonce = models.CharField(max_length=64)
    uploaded_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)
    change_summary = models.CharField(max_length=255, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-version_number']
        unique_together = ('file_record', 'version_number')

    def __str__(self):
        return f"{self.file_record.display_name} v{self.version_number}"

    @property
    def formatted_size(self):
        size = self.file_size
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} TB"
