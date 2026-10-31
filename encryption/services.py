import uuid
import os
from pathlib import Path
from django.conf import settings
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

from .key_manager import generate_dek, generate_nonce, wrap_dek, unwrap_dek
from .integrity import calculate_bytes_sha256, verify_integrity

class DecryptionIntegrityError(Exception):
    """Raised when AES-GCM tag or SHA-256 verification fails."""
    pass

def encrypt_file_data(file_bytes: bytes) -> dict:
    """
    Core AES-256-GCM encryption service:
    1. Calculate original file's SHA-256 hash.
    2. Generate unique random 256-bit DEK.
    3. Generate unique random 96-bit Nonce.
    4. Encrypt using AES-256-GCM (producing ciphertext with integrated authentication tag).
    5. Wrap DEK using Master KEK.
    6. Save encrypted payload into protected storage.
    7. Return metadata dictionary.
    """
    original_sha256 = calculate_bytes_sha256(file_bytes)
    dek = generate_dek()
    nonce = generate_nonce()

    aesgcm = AESGCM(dek)
    # Ciphertext includes the 128-bit authentication tag appended
    ciphertext = aesgcm.encrypt(nonce, file_bytes, None)

    # Wrap the DEK with Master KEK
    wrapped_dek_hex = wrap_dek(dek)

    # Generate a unique server-side storage filename outside web root
    storage_uuid = str(uuid.uuid4())
    stored_filename = f"{storage_uuid}.enc"
    storage_path = settings.PRIVATE_STORAGE_DIR / stored_filename

    with open(storage_path, 'wb') as f:
        f.write(ciphertext)

    return {
        'stored_filename': stored_filename,
        'original_size': len(file_bytes),
        'encrypted_size': len(ciphertext),
        'sha256_hash': original_sha256,
        'wrapped_dek': wrapped_dek_hex,
        'nonce_hex': nonce.hex(),
    }

def decrypt_file_data(stored_filename: str, wrapped_dek_hex: str, nonce_hex: str, expected_sha256: str) -> bytes:
    """
    Core AES-256-GCM decryption service:
    1. Unwrap the DEK using Master KEK.
    2. Read encrypted ciphertext from private storage.
    3. Decrypt and verify authentication tag using AES-256-GCM.
    4. Calculate decrypted plaintext SHA-256 hash.
    5. Compare against expected hash.
    6. Return verified plaintext bytes.
    """
    storage_path = settings.PRIVATE_STORAGE_DIR / stored_filename
    if not storage_path.exists():
        raise FileNotFoundError(f"Encrypted storage file '{stored_filename}' does not exist.")

    # 1. Unwrap DEK
    dek = unwrap_dek(wrapped_dek_hex)
    nonce = bytes.fromhex(nonce_hex)

    # 2. Read ciphertext
    with open(storage_path, 'rb') as f:
        ciphertext = f.read()

    # 3. Decrypt and verify AES-GCM tag
    try:
        aesgcm = AESGCM(dek)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    except InvalidTag:
        raise DecryptionIntegrityError("AES-256-GCM Authentication Tag verification failed! File has been tampered with or corrupted.")
    except Exception as e:
        raise DecryptionIntegrityError(f"Decryption error: {e}")

    # 4. SHA-256 Integrity Verification
    decrypted_sha256 = calculate_bytes_sha256(plaintext)
    if not verify_integrity(decrypted_sha256, expected_sha256):
        raise DecryptionIntegrityError(
            f"SHA-256 integrity mismatch! Expected {expected_sha256}, calculated {decrypted_sha256}"
        )

    return plaintext

def delete_encrypted_file(stored_filename: str):
    """
    Safely delete encrypted storage file from disk.
    """
    try:
        storage_path = settings.PRIVATE_STORAGE_DIR / stored_filename
        if storage_path.exists():
            os.remove(storage_path)
    except Exception as e:
        print(f"Error removing encrypted file {stored_filename}: {e}")
