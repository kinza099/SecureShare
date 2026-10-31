import os
from django.test import TestCase
from encryption.services import encrypt_file_data, decrypt_file_data, DecryptionIntegrityError
from encryption.key_manager import generate_dek, generate_nonce, wrap_dek, unwrap_dek
from encryption.integrity import calculate_bytes_sha256, verify_integrity

class CryptographicEngineTests(TestCase):
    def setUp(self):
        self.plain_data = b"CONFIDENTIAL SSDD LAB FILE CONTENT - AES-256-GCM"

    def test_tc_crypto_01_aes_gcm_round_trip(self):
        """TC-CRYPTO-01: Encrypt and decrypt round trip recovers exact plaintext."""
        enc_meta = encrypt_file_data(self.plain_data)
        decrypted = decrypt_file_data(
            stored_filename=enc_meta['stored_filename'],
            wrapped_dek_hex=enc_meta['wrapped_dek'],
            nonce_hex=enc_meta['nonce_hex'],
            expected_sha256=enc_meta['sha256_hash']
        )
        self.assertEqual(decrypted, self.plain_data, "Decrypted data must match original plaintext exactly.")

    def test_tc_crypto_02_kek_wrapping(self):
        """TC-CRYPTO-02: Key wrap and unwrap returns original 32-byte DEK."""
        dek = generate_dek()
        wrapped_hex = wrap_dek(dek)
        unwrapped = unwrap_dek(wrapped_hex)
        self.assertEqual(dek, unwrapped, "Unwrapped DEK must match original generated DEK.")
        self.assertEqual(len(unwrapped), 32, "DEK must be exactly 256 bits (32 bytes).")

    def test_tc_crypto_03_tag_tamper_detection(self):
        """TC-CRYPTO-03: Ciphertext bit flipping must trigger DecryptionIntegrityError."""
        from django.conf import settings
        enc_meta = encrypt_file_data(self.plain_data)
        file_path = settings.PRIVATE_STORAGE_DIR / enc_meta['stored_filename']

        # Tamper with the encrypted ciphertext on disk
        with open(file_path, 'r+b') as f:
            data = bytearray(f.read())
            data[0] ^= 0xFF  # Flip bits in first byte
            f.seek(0)
            f.write(data)

        with self.assertRaises(DecryptionIntegrityError):
            decrypt_file_data(
                stored_filename=enc_meta['stored_filename'],
                wrapped_dek_hex=enc_meta['wrapped_dek'],
                nonce_hex=enc_meta['nonce_hex'],
                expected_sha256=enc_meta['sha256_hash']
            )

    def test_tc_crypto_04_sha256_verification(self):
        """TC-CRYPTO-04: Plaintext SHA-256 mismatch detection."""
        enc_meta = encrypt_file_data(self.plain_data)
        bogus_hash = "0" * 64

        with self.assertRaises(DecryptionIntegrityError):
            decrypt_file_data(
                stored_filename=enc_meta['stored_filename'],
                wrapped_dek_hex=enc_meta['wrapped_dek'],
                nonce_hex=enc_meta['nonce_hex'],
                expected_sha256=bogus_hash
            )

    def test_tc_crypto_05_nonce_uniqueness(self):
        """TC-CRYPTO-05: Nonces generated for consecutive encryptions must never repeat."""
        nonces = set()
        for _ in range(50):
            n = generate_nonce()
            self.assertNotIn(n, nonces, "Nonce was duplicated!")
            nonces.add(n)
        self.assertEqual(len(nonces), 50)
