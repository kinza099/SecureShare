import os
import secrets
from django.conf import settings
from cryptography.hazmat.primitives.keywrap import aes_key_wrap, aes_key_unwrap

class KeyManagementError(Exception):
    """Custom exception raised when key wrapping/unwrapping fails."""
    pass

def get_master_kek() -> bytes:
    """
    Retrieve the 256-bit (32 bytes) Master Key Encryption Key (KEK) from Django settings.
    If not found in environment, checks or creates a secured local keyfile.
    """
    kek_hex = getattr(settings, 'MASTER_KEK', '')
    if kek_hex and len(kek_hex.strip()) == 64:
        try:
            return bytes.fromhex(kek_hex.strip())
        except ValueError:
            pass

    # Fallback to protected keyfile if env var was not provided
    keyfile_path = settings.BASE_DIR / '.master_kek'
    if keyfile_path.exists():
        with open(keyfile_path, 'rb') as f:
            key_data = f.read().strip()
            if len(key_data) == 32:
                return key_data
            elif len(key_data) == 64:
                return bytes.fromhex(key_data.decode('ascii'))

    # Generate and persist keyfile
    new_kek = secrets.token_bytes(32)
    with open(keyfile_path, 'wb') as f:
        f.write(new_kek.hex().encode('ascii'))
    return new_kek

def generate_dek() -> bytes:
    """
    Generate a cryptographically secure 256-bit random Data Encryption Key (DEK).
    """
    return secrets.token_bytes(32)

def generate_nonce() -> bytes:
    """
    Generate a standard 96-bit (12 bytes) unique Nonce for AES-GCM.
    """
    return secrets.token_bytes(12)

def wrap_dek(dek: bytes) -> str:
    """
    Wrap a 256-bit DEK with the 256-bit Master KEK using NIST SP 800-38F Key Wrap.
    Returns a hex-encoded string suitable for database storage.
    """
    kek = get_master_kek()
    try:
        wrapped_bytes = aes_key_wrap(kek, dek)
        return wrapped_bytes.hex()
    except Exception as e:
        raise KeyManagementError(f"Failed to wrap DEK: {e}")

def unwrap_dek(wrapped_dek_hex: str) -> bytes:
    """
    Unwrap the hex-encoded wrapped DEK back into raw 32-byte DEK in memory.
    The raw DEK is never saved to the database.
    """
    kek = get_master_kek()
    try:
        wrapped_bytes = bytes.fromhex(wrapped_dek_hex.strip())
        return aes_key_unwrap(kek, wrapped_bytes)
    except Exception as e:
        raise KeyManagementError(f"Failed to unwrap DEK (Invalid key or corruption): {e}")
