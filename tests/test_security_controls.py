from django.test import TestCase, Client
from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.urls import reverse
from filemanager.services import process_file_upload
from encryption.validator import validate_uploaded_file
from django.core.exceptions import ValidationError

User = get_user_model()

class SecurityControlsTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.alice = User.objects.create_user(username='alice', password='Password@123', email='alice@test.local')
        self.bob = User.objects.create_user(username='bob', password='Password@123', email='bob@test.local')

        pdf = SimpleUploadedFile("alice_secrets.pdf", b"%PDF-1.4 Alice Private File", content_type="application/pdf")
        self.alice_file = process_file_upload(self.alice, pdf, display_name="Alice Secret File")

    def test_tc_sec_01_idor_file_access_prevention(self):
        """TC-SEC-01: Insecure Direct Object Reference (IDOR) prevention."""
        self.client.login(username='bob', password='Password@123')
        # Bob attempts to download Alice's private unshared file directly via UUID
        download_url = f"/files/download/{self.alice_file.id}/"
        response = self.client.get(download_url)
        self.assertEqual(response.status_code, 403, "IDOR attempt must be blocked with HTTP 403 Forbidden.")

    def test_tc_sec_02_executable_upload_rejection(self):
        """TC-SEC-02: Blacklisted executable scripts must be rejected."""
        dangerous_names = ["malware.exe", "backdoor.sh", "payload.bat", "script.py", "shell.php"]
        for name in dangerous_names:
            fake_file = SimpleUploadedFile(name, b"echo Attack", content_type="application/octet-stream")
            with self.assertRaises(ValidationError):
                validate_uploaded_file(fake_file)

    def test_tc_sec_03_magic_byte_validation(self):
        """TC-SEC-03: Extension spoofing detected via magic byte verification."""
        # File named .pdf but containing plain text without %PDF header
        spoofed_file = SimpleUploadedFile("fake.pdf", b"This is not a real PDF file header", content_type="application/pdf")
        with self.assertRaises(ValidationError):
            validate_uploaded_file(spoofed_file)

    def test_tc_sec_04_duplicate_detection(self):
        """TC-SEC-04: Duplicate detection warns user when uploading identical content."""
        from filemanager.services import check_file_duplicate_for_user
        duplicate = check_file_duplicate_for_user(self.alice, b"%PDF-1.4 Alice Private File")
        self.assertIsNotNone(duplicate, "Duplicate file must be detected within user account.")

        # Must NOT expose duplicate across different users
        diff_user_dup = check_file_duplicate_for_user(self.bob, b"%PDF-1.4 Alice Private File")
        self.assertIsNone(diff_user_dup, "Duplicate detection must not leak other users' files.")

    def test_tc_sec_05_security_headers(self):
        """TC-SEC-05: Strict security headers on sensitive responses."""
        self.client.login(username='alice', password='Password@123')
        download_url = f"/files/download/{self.alice_file.id}/"
        response = self.client.get(download_url)
        self.assertEqual(response.headers.get('X-Content-Type-Options'), 'nosniff')
