from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone
from datetime import timedelta

class User(AbstractUser):
    """
    Custom user model for Secure File Sharing System.
    Includes Argon2id hashed passwords, RBAC attributes, lockout protection, and 2FA attributes.
    """
    full_name = models.CharField(max_length=150, blank=True)
    is_admin = models.BooleanField(default=False, help_text="Designates whether the user has administrative privileges.")
    is_suspended = models.BooleanField(default=False, help_text="Designates whether this account is deactivated.")
    failed_login_attempts = models.PositiveIntegerField(default=0)
    lockout_until = models.DateTimeField(null=True, blank=True)
    last_login_ip = models.GenericIPAddressField(null=True, blank=True)
    two_factor_enabled = models.BooleanField(default=False)
    totp_secret = models.CharField(max_length=64, blank=True, null=True)

    def is_locked(self):
        """Check if account is temporarily locked due to multiple failed login attempts."""
        if self.lockout_until and timezone.now() < self.lockout_until:
            return True
        return False

    def reset_failed_attempts(self):
        """Reset failed login count and clear lockout."""
        self.failed_login_attempts = 0
        self.lockout_until = None
        self.save(update_fields=['failed_login_attempts', 'lockout_until'])

    def increment_failed_attempts(self, max_attempts=5, lockout_minutes=15):
        """Record a failed login and apply temporary lockout if threshold reached."""
        self.failed_login_attempts += 1
        if self.failed_login_attempts >= max_attempts:
            self.lockout_until = timezone.now() + timedelta(minutes=lockout_minutes)
        self.save(update_fields=['failed_login_attempts', 'lockout_until'])

    def __str__(self):
        return f"{self.username} ({'Admin' if self.is_admin else 'User'})"


class LoginHistory(models.Model):
    """
    Audit log for user authentication attempts.
    """
    STATUS_CHOICES = [
        ('SUCCESS', 'Login Successful'),
        ('FAILED_PASSWORD', 'Invalid Password'),
        ('FAILED_USER', 'User Not Found'),
        ('LOCKED_OUT', 'Account Locked Out'),
        ('SUSPENDED', 'Account Suspended'),
    ]

    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='login_history')
    username_attempted = models.CharField(max_length=150)
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField(blank=True)
    status = models.CharField(max_length=30, choices=STATUS_CHOICES)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['ip_address', 'timestamp']),
            models.Index(fields=['username_attempted', 'status']),
        ]

    def __str__(self):
        return f"Login {self.status} for {self.username_attempted} from {self.ip_address} at {self.timestamp}"
