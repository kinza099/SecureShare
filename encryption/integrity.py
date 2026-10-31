import hashlib
import hmac

def calculate_bytes_sha256(data: bytes) -> str:
    """
    Calculate the SHA-256 digest of in-memory bytes.
    """
    hasher = hashlib.sha256()
    hasher.update(data)
    return hasher.hexdigest().lower()

def calculate_stream_sha256(file_obj, chunk_size=65536) -> str:
    """
    Calculate the SHA-256 digest of a file-like stream without loading it entirely into memory.
    Resets the file pointer to 0 when finished.
    """
    hasher = hashlib.sha256()
    file_obj.seek(0)
    while True:
        chunk = file_obj.read(chunk_size)
        if not chunk:
            break
        hasher.update(chunk)
    file_obj.seek(0)
    return hasher.hexdigest().lower()

def calculate_file_sha256(file_path, chunk_size=65536) -> str:
    """
    Calculate the SHA-256 digest of a disk file.
    """
    hasher = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest().lower()

def verify_integrity(calculated_hash: str, expected_hash: str) -> bool:
    """
    Compare two SHA-256 digests in constant time using hmac.compare_digest.
    """
    if not calculated_hash or not expected_hash:
        return False
    return hmac.compare_digest(calculated_hash.strip().lower(), expected_hash.strip().lower())
