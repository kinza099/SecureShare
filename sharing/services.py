import io
import secrets
import qrcode
from datetime import timedelta
from django.utils import timezone
from django.contrib.auth.hashers import make_password, check_password
from django.db import transaction
from django.core.exceptions import ValidationError

from .models import FileShare, SharingLink
from encryption.integrity import calculate_bytes_sha256
from notifications.services import create_notification
from monitoring.services import log_activity, trigger_security_alert

def create_user_share(sender, file_record, recipient, permission='DOWNLOADER', message='', expiration_hours=None, request=None):
    """
    Share a file directly with another registered user.
    """
    if file_record.owner != sender:
        raise ValidationError("Only the file owner can share this file.")
    if sender == recipient:
        raise ValidationError("You cannot share a file with yourself.")

    expires_at = None
    if expiration_hours:
        expires_at = timezone.now() + timedelta(hours=expiration_hours)

    share, created = FileShare.objects.update_or_create(
        file_record=file_record,
        recipient=recipient,
        defaults={
            'sender': sender,
            'permission': permission,
            'message': message,
            'expires_at': expires_at,
            'is_revoked': False,
        }
    )

    # In-app notification to recipient
    create_notification(
        user=recipient,
        title="File Shared with You",
        message=f"{sender.full_name or sender.username} shared '{file_record.display_name}' with you ({permission.capitalize()}).",
        notification_type='FILE_SHARED',
        link_url='/sharing/received/'
    )

    log_activity(
        request=request,
        user=sender,
        event_type='FILE_SHARE',
        resource_id=str(file_record.id),
        description=f"Shared '{file_record.display_name}' with user '{recipient.username}' ({permission})",
        status='SUCCESS'
    )

    return share

def generate_link_token() -> tuple[str, str]:
    """
    Generate an unguessable 256-bit URL-safe token.
    Returns (raw_public_token, token_sha256_hash).
    Only the hash is persisted in the database.
    """
    raw_token = secrets.token_urlsafe(32)
    token_hash = calculate_bytes_sha256(raw_token.encode('ascii'))
    return raw_token, token_hash

def create_secure_sharing_link(creator, file_record, password=None, expiration_hours=24, max_downloads=None, request=None):
    """
    Create a password-protected, rate-limited public sharing link.
    """
    if file_record.owner != creator:
        raise ValidationError("Only the file owner can create sharing links.")

    raw_token, token_hash = generate_link_token()

    expires_at = None
    if expiration_hours:
        expires_at = timezone.now() + timedelta(hours=expiration_hours)

    password_hash = ''
    is_protected = False
    if password and password.strip():
        password_hash = make_password(password.strip())
        is_protected = True

    link = SharingLink.objects.create(
        file_record=file_record,
        creator=creator,
        token_hash=token_hash,
        is_password_protected=is_protected,
        password_hash=password_hash,
        max_downloads=max_downloads,
        expires_at=expires_at,
    )

    log_activity(
        request=request,
        user=creator,
        event_type='LINK_CREATE',
        resource_id=str(file_record.id),
        description=f"Created sharing link for '{file_record.display_name}' (Protected: {is_protected}, Max DL: {max_downloads or 'Unlimited'})",
        status='SUCCESS'
    )

    return link, raw_token

def generate_qr_code_png(url_target: str) -> bytes:
    """
    Generate a QR code image as PNG bytes.
    Does NOT contain passwords or keys, only the direct URL endpoint.
    """
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=10,
        border=3,
    )
    qr.add_data(url_target)
    qr.make(fit=True)

    img = qr.make_image(fill_color="#0a192f", back_color="#ffffff")
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    return buffer.getvalue()
