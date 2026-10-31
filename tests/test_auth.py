from django.test import TestCase, Client
from django.contrib.auth import get_user_model
from django.urls import reverse
from accounts.forms import RegisterForm

User = get_user_model()

class AuthenticationSecurityTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='TestUser@123'
        )
        self.admin = User.objects.create_user(
            username='testadmin',
            email='admin@example.com',
            password='AdminPassword@123',
            is_admin=True
        )

    def test_tc_auth_01_registration_password_policy(self):
        """TC-AUTH-01: Strong password enforcement during registration."""
        weak_passwords = ['short1!', 'ALLUPPERCASE1!', 'alllowercase1!', 'NoDigitsHere!']
        for weak in weak_passwords:
            form = RegisterForm(data={
                'full_name': 'Test User',
                'username': 'unique_user_99',
                'email': 'unique@example.com',
                'password': weak,
                'confirm_password': weak
            })
            self.assertFalse(form.is_valid(), f"Weak password '{weak}' should have been rejected.")

    def test_tc_auth_02_argon2id_hashing(self):
        """TC-AUTH-02: Verification of Argon2id password hash storage."""
        self.assertTrue(self.user.password.startswith('argon2'), "Password must be hashed with Argon2id.")

    def test_tc_auth_03_lockout_after_failures(self):
        """TC-AUTH-03: Account lockout after 5 failed login attempts."""
        login_url = reverse('accounts:login')
        for i in range(5):
            response = self.client.post(login_url, {
                'username_or_email': 'testuser',
                'password': 'WrongPassword123'
            })
        self.user.refresh_from_db()
        self.assertTrue(self.user.is_locked(), "User must be locked out after 5 failed login attempts.")

    def test_tc_auth_04_admin_rbac_isolation(self):
        """TC-AUTH-04: Standard users must be denied access to admin control routes."""
        self.client.login(username='testuser', password='TestUser@123')
        admin_url = reverse('monitoring:admin_users')
        response = self.client.get(admin_url)
        # Should redirect to login or return 302 due to user_passes_test
        self.assertNotEqual(response.status_code, 200, "Standard user should not access admin endpoints.")

    def test_tc_auth_05_suspended_user_rejection(self):
        """TC-AUTH-05: Suspended user login rejection."""
        self.user.is_suspended = True
        self.user.save()
        response = self.client.post(reverse('accounts:login'), {
            'username_or_email': 'testuser',
            'password': 'TestUser@123'
        })
        self.assertNotIn('_auth_user_id', self.client.session, "Suspended user must not be logged in.")
