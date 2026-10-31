import os
import mimetypes
from django.db import transaction
from django.core.exceptions import PermissionDenied
from .models import FileRecord, FileEncryptionMetadata, FileVersion
from encryption.services import encrypt_file_data, decrypt_file_data, delete_encrypted_file, DecryptionIntegrityError
from encryption.integrity import calculate_bytes_sha256
from notifications.services import create_notification
from monitoring.services import log_activity, trigger_security_alert

def check_file_duplicate_for_user(user, file_bytes):
    """
    Detect if an identical file content (same SHA-256) already exists in this user's account.
    Maintains confidentiality: does not check or expose other users' files.
    """
    file_hash = calculate_bytes_sha256(file_bytes)
    return FileRecord.objects.filter(owner=user, sha256_hash=file_hash, is_deleted=False).first()

@transaction.atomic
def process_file_upload(user, uploaded_file, display_name=None, request=None):
    """
    Handles complete secure file upload, encryption, and metadata storage.
    """
    file_bytes = uploaded_file.read()
    orig_filename = uploaded_file.name
    ext = os.path.splitext(orig_filename)[1].lower().lstrip('.')

    # Encrypt via AES-256-GCM
    enc_meta = encrypt_file_data(file_bytes)

    # Create file record
    record = FileRecord.objects.create(
        owner=user,
        display_name=display_name.strip() if display_name and display_name.strip() else orig_filename,
        original_filename=orig_filename,
        file_type=ext,
        file_size=enc_meta['original_size'],
        sha256_hash=enc_meta['sha256_hash'],
        current_version=1,
    )

    # Create encryption metadata record
    FileEncryptionMetadata.objects.create(
        file_record=record,
        stored_filename=enc_meta['stored_filename'],
        wrapped_dek=enc_meta['wrapped_dek'],
        nonce=enc_meta['nonce_hex'],
        algorithm='AES-256-GCM',
        key_wrap_algorithm='NIST-SP-800-38F-KW',
        integrity_status='VERIFIED',
    )

    # Create initial version 1
    FileVersion.objects.create(
        file_record=record,
        version_number=1,
        stored_filename=enc_meta['stored_filename'],
        file_size=enc_meta['original_size'],
        sha256_hash=enc_meta['sha256_hash'],
        wrapped_dek=enc_meta['wrapped_dek'],
        nonce=enc_meta['nonce_hex'],
        uploaded_by=user,
        change_summary='Initial upload',
    )

    # In-app notification
    create_notification(
        user=user,
        title="File Encrypted and Saved",
        message=f"File '{record.display_name}' has been encrypted with AES-256-GCM and stored securely.",
        notification_type='FILE_UPLOAD',
        link_url=f"/files/details/{record.id}/"
    )

    # Activity log
    log_activity(
        request=request,
        user=user,
        event_type='FILE_UPLOAD',
        resource_id=str(record.id),
        description=f"Uploaded and encrypted '{record.display_name}' ({record.formatted_size})",
        status='SUCCESS'
    )

    return record

@transaction.atomic
def process_new_version(user, file_record, uploaded_file, change_summary='', request=None):
    """
    Encrypt and attach a new version to an existing FileRecord.
    """
    if file_record.owner != user:
        raise PermissionDenied("Only the file owner can upload new versions.")

    file_bytes = uploaded_file.read()
    enc_meta = encrypt_file_data(file_bytes)
    new_version_num = file_record.current_version + 1

    # Create version record
    version = FileVersion.objects.create(
        file_record=file_record,
        version_number=new_version_num,
        stored_filename=enc_meta['stored_filename'],
        file_size=enc_meta['original_size'],
        sha256_hash=enc_meta['sha256_hash'],
        wrapped_dek=enc_meta['wrapped_dek'],
        nonce=enc_meta['nonce_hex'],
        uploaded_by=user,
        change_summary=change_summary or f"Version {new_version_num}",
    )

    # Update active FileRecord metadata
    file_record.current_version = new_version_num
    file_record.file_size = enc_meta['original_size']
    file_record.sha256_hash = enc_meta['sha256_hash']
    file_record.save(update_fields=['current_version', 'file_size', 'sha256_hash', 'updated_at'])

    meta = file_record.encryption_metadata
    meta.stored_filename = enc_meta['stored_filename']
    meta.wrapped_dek = enc_meta['wrapped_dek']
    meta.nonce = enc_meta['nonce_hex']
    meta.integrity_status = 'VERIFIED'
    meta.save()

    create_notification(
        user=user,
        title="New File Version Uploaded",
        message=f"Version {new_version_num} of '{file_record.display_name}' is now active.",
        notification_type='VERSION_UPLOADED',
        link_url=f"/files/versions/{file_record.id}/"
    )

    log_activity(
        request=request,
        user=user,
        event_type='FILE_UPLOAD',
        resource_id=str(file_record.id),
        description=f"Uploaded v{new_version_num} for '{file_record.display_name}'",
        status='SUCCESS'
    )

    return version

def retrieve_and_decrypt_file(file_record, version_number=None, request=None, audit_user=None):
    """
    Decrypts and verifies authenticated file content.
    """
    if version_number and version_number != file_record.current_version:
        v_record = file_record.versions.filter(version_number=version_number).first()
        if not v_record:
            raise FileNotFoundError(f"Version {version_number} not found.")
        stored_filename = v_record.stored_filename
        wrapped_dek = v_record.wrapped_dek
        nonce = v_record.nonce
        expected_sha256 = v_record.sha256_hash
    else:
        meta = file_record.encryption_metadata
        stored_filename = meta.stored_filename
        wrapped_dek = meta.wrapped_dek
        nonce = meta.nonce
        expected_sha256 = file_record.sha256_hash

    try:
        plaintext = decrypt_file_data(
            stored_filename=stored_filename,
            wrapped_dek_hex=wrapped_dek,
            nonce_hex=nonce,
            expected_sha256=expected_sha256
        )
        return plaintext
    except DecryptionIntegrityError as e:
        trigger_security_alert(
            rule_name="File Integrity Tampering Detected",
            description=f"Decryption/SHA-256 integrity check failed for file '{file_record.display_name}' (ID: {file_record.id}): {e}",
            severity='CRITICAL',
            user=audit_user,
            request=request
        )
        if hasattr(file_record, 'encryption_metadata'):
            file_record.encryption_metadata.integrity_status = 'FAILED'
            file_record.encryption_metadata.save(update_fields=['integrity_status'])
        raise
