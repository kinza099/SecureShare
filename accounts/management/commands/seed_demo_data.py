from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from filemanager.services import process_file_upload
from sharing.services import create_user_share, create_secure_sharing_link
from monitoring.services import log_activity, trigger_security_alert

User = get_user_model()

class Command(BaseCommand):
    help = "Seed initial demonstration accounts, encrypted files, and sharing links for SSDD Lab demonstration."

    def handle(self, *args, **options):
        self.stdout.write("Seeding demo accounts and security test data...")

        # 1. Admin Account
        admin_user, created = User.objects.get_or_create(
            username='admin',
            defaults={
                'email': 'admin@ssdd.local',
                'full_name': 'Chief Security Administrator',
                'is_admin': True,
                'is_staff': True,
                'is_superuser': True,
            }
        )
        admin_user.set_password('Admin@12345')
        admin_user.is_admin = True
        admin_user.is_staff = True
        admin_user.is_superuser = True
        admin_user.save()
        self.stdout.write("  -> Admin: admin / Admin@12345")

        # 2. User A (Alice - Researcher)
        alice, _ = User.objects.get_or_create(
            username='alice',
            defaults={
                'email': 'alice@ssdd.local',
                'full_name': 'Alice Johnson',
            }
        )
        alice.set_password('Alice@12345')
        alice.save()
        self.stdout.write("  -> User A: alice / Alice@12345")

        # 3. User B (Bob - Analyst)
        bob, _ = User.objects.get_or_create(
            username='bob',
            defaults={
                'email': 'bob@ssdd.local',
                'full_name': 'Bob Smith',
            }
        )
        bob.set_password('Bob@12345')
        bob.save()
        self.stdout.write("  -> User B: bob / Bob@12345")

        # 4. User C (Charlie - Auditor)
        charlie, _ = User.objects.get_or_create(
            username='charlie',
            defaults={
                'email': 'charlie@ssdd.local',
                'full_name': 'Charlie Davis',
            }
        )
        charlie.set_password('Charlie@12345')
        charlie.save()
        self.stdout.write("  -> User C: charlie / Charlie@12345")

        # 5. Upload sample files for Alice
        if not alice.files.filter(is_deleted=False).exists():
            sample_content = b"%PDF-1.5 Confidential SSDD Security Evaluation Report.\nAll rights reserved.\nAES-256-GCM encrypted."
            pdf_file = SimpleUploadedFile("Security_Assessment_2026.pdf", sample_content, content_type="application/pdf")
            file_rec = process_file_upload(alice, pdf_file, display_name="Annual Security Assessment")

            # Share with Bob
            create_user_share(alice, file_rec, bob, permission='DOWNLOADER', message="Hi Bob, review the confidential audit report.")

            # Create a public sharing link
            create_secure_sharing_link(alice, file_rec, password="SecretPassword123", expiration_hours=48, max_downloads=10)

            self.stdout.write("  -> Encrypted file uploaded for Alice and shared with Bob.")

        # 6. Sample Security Event for Threat Detection demo
        trigger_security_alert(
            rule_name="Multiple Failed Login Attempts",
            description="5 consecutive invalid password submissions detected for user account 'charlie' from IP 192.168.1.150.",
            severity='HIGH',
            user=charlie,
            ip_address='192.168.1.150'
        )

        self.stdout.write(self.style.SUCCESS("SSDD demo data successfully initialized!"))
