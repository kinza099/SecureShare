import os
from django.conf import settings
from django.core.exceptions import ValidationError

DANGEROUS_EXTENSIONS = {
    'exe', 'bat', 'cmd', 'sh', 'ps1', 'vbs', 'msi', 'scr', 'dll', 'com', 'pif',
    'php', 'jsp', 'asp', 'aspx', 'py', 'pl', 'cgi', 'jar', 'war'
}

def validate_uploaded_file(uploaded_file):
    """
    Rigorously validate an uploaded file:
    1. Maximum file size check.
    2. File extension validation.
    3. Blacklist check against executable / script extensions.
    4. Magic byte signature verification.
    5. Directory traversal / filename manipulation check.
    """
    # 1. Size check
    max_bytes = getattr(settings, 'DATA_UPLOAD_MAX_MEMORY_SIZE', 50 * 1024 * 1024)
    if uploaded_file.size > max_bytes:
        max_mb = max_bytes // (1024 * 1024)
        raise ValidationError(f"File size ({uploaded_file.size / (1024*1024):.1f} MB) exceeds maximum allowed limit of {max_mb} MB.")

    if uploaded_file.size == 0:
        raise ValidationError("Uploaded file is empty (0 bytes).")

    # 2. Filename and extension check
    filename = uploaded_file.name
    if not filename or '/' in filename or '\\' in filename:
        raise ValidationError("Invalid filename syntax or directory traversal attempt.")

    ext = os.path.splitext(filename)[1].lower().lstrip('.')
    if not ext:
        raise ValidationError("Files without an extension are not allowed.")

    if ext in DANGEROUS_EXTENSIONS:
        raise ValidationError(f"Execution security violation: Files with extension '.{ext}' are prohibited.")

    allowed_exts = getattr(settings, 'ALLOWED_FILE_EXTENSIONS', [])
    if ext not in allowed_exts:
        raise ValidationError(f"Unsupported file format '.{ext}'. Allowed types: {', '.join(allowed_exts)}.")

    # 3. Magic byte signature verification
    signatures = getattr(settings, 'FILE_MAGIC_SIGNATURES', {}).get(ext, [])
    if signatures:
        uploaded_file.seek(0)
        header = uploaded_file.read(32)
        uploaded_file.seek(0)

        match_found = any(header.startswith(sig) for sig in signatures)
        if not match_found:
            raise ValidationError(
                f"File integrity mismatch: Content header does not match expected signature for '{ext.upper()}' files."
            )
    elif ext in ['txt', 'csv']:
        # For text files, verify that content is valid text and contains no suspicious binary null bytes
        uploaded_file.seek(0)
        sample = uploaded_file.read(4096)
        uploaded_file.seek(0)
        if b'\x00' in sample:
            raise ValidationError("Binary or corrupted content detected inside text file.")
        try:
            sample.decode('utf-8', errors='strict')
        except UnicodeDecodeError:
            try:
                sample.decode('latin-1', errors='strict')
            except UnicodeDecodeError:
                raise ValidationError("Invalid text encoding in uploaded file.")

    return True
