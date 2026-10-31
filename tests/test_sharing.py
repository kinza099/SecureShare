from datetime import timedelta
from django.test import TestCase, Client
from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.utils import timezone
from filemanager.services import process_file_upload
from sharing.services import create_user_share, create_secure_sharing_link
from sharing.models import SharingLink

User = get_user_model()

class SharingSecurityTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.alice = User.objects.create_user(username='alice', password='Password@123', email='alice@test.local')
        self.bob = User.objects.create_user(username='bob', password='Password@123', email='bob@test.local')
        self.charlie = User.objects.create_user(username='charlie', password='Password@123', email='charlie@test.local')

        pdf = SimpleUploadedFile("confidential.pdf", b"%PDF-1.4 SSDD Test Content", content_type="application/pdf")
        self.file_rec = process_file_upload(self.alice, pdf, display_name="Confidential Report")

    def test_tc_share_01_viewer_permission_restriction(self):
        """TC-SHARE-01: Viewer permission cannot download file directly."""
        share = create_user_share(self.alice, self.file_rec, self.bob, permission='VIEWER')
        self.client.login(username='bob', password='Password@123')

        download_url = f"/files/download/{self.file_rec.id}/"
        response = self.client.get(download_url)
        # Should be forbidden 403
        self.assertEqual(response.status_code, 403, "Viewer should not be able to download the file.")

    def test_tc_share_02_password_protected_link(self):
        """TC-SHARE-02: Password-protected link requires valid password."""
        link, raw_token = create_secure_sharing_link(
            self.alice, self.file_rec, password="SecretPassword123"
        )
        access_url = f"/sharing/access/{raw_token}/"

        # 1. Access without password should prompt for password
        response = self.client.get(access_url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "This link is protected with a password")

        # 2. Submit wrong password
        response = self.client.post(access_url, {'password': 'WrongPassword!', 'verify_password': '1'})
        self.assertContains(response, "Incorrect password")

        # 3. Submit valid password
        response = self.client.post(access_url, {'password': 'SecretPassword123', 'verify_password': '1'})
        self.assertContains(response, "Decrypt & Download File")

    def test_tc_share_03_link_expiration(self):
        """TC-SHARE-03: Expired link returns 403 / Link Expired."""
        link, raw_token = create_secure_sharing_link(self.alice, self.file_rec, expiration_hours=1)
        # Fast-forward time
        link.expires_at = timezone.now() - timedelta(minutes=10)
        link.save()

        access_url = f"/sharing/access/{raw_token}/"
        response = self.client.get(access_url)
        self.assertEqual(response.status_code, 403)
        self.assertContains(response, "expired", status_code=403)

    def test_tc_share_04_link_revocation(self):
        """TC-SHARE-04: Revoked link denies access."""
        link, raw_token = create_secure_sharing_link(self.alice, self.file_rec)
        link.is_revoked = True
        link.save()

        access_url = f"/sharing/access/{raw_token}/"
        response = self.client.get(access_url)
        self.assertEqual(response.status_code, 403)
        self.assertContains(response, "revoked", status_code=403)

    def test_tc_share_05_max_downloads_enforcement(self):
        """TC-SHARE-05: Download limit is strictly enforced."""
        link, raw_token = create_secure_sharing_link(self.alice, self.file_rec, max_downloads=1)
        access_url = f"/sharing/access/{raw_token}/"

        # First download - success
        response = self.client.post(access_url, {'download_file': '1'})
        self.assertEqual(response.status_code, 200)

        # Second download attempt - denied
        response2 = self.client.post(access_url, {'download_file': '1'})
        self.assertEqual(response2.status_code, 403)
