from django import forms
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from .models import FileShare, SharingLink

User = get_user_model()

class DirectShareForm(forms.Form):
    recipient_identifier = forms.CharField(
        label="Recipient Username or Email",
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter recipient username or email'})
    )
    permission = forms.ChoiceField(
        choices=FileShare.PERMISSION_CHOICES,
        widget=forms.Select(attrs={'class': 'form-select'})
    )
    message = forms.CharField(
        label="Message (Optional)",
        required=False,
        widget=forms.Textarea(attrs={'class': 'form-control', 'rows': 2, 'placeholder': 'Add a note for the recipient...'})
    )
    expiration_hours = forms.IntegerField(
        label="Access Expiration (Hours, optional)",
        required=False,
        min_value=1,
        max_value=720,  # up to 30 days
        widget=forms.NumberInput(attrs={'class': 'form-control', 'placeholder': 'e.g. 24 (Leave blank for no expiration)'})
    )

    def clean_recipient_identifier(self):
        ident = self.cleaned_data.get('recipient_identifier', '').strip()
        if '@' in ident:
            user = User.objects.filter(email__iexact=ident, is_active=True).first()
        else:
            user = User.objects.filter(username__iexact=ident, is_active=True).first()

        if not user:
            raise ValidationError(f"No active registered user found matching '{ident}'.")
        return user


class CreateSharingLinkForm(forms.Form):
    enable_password = forms.BooleanField(
        label="Enable Password Protection",
        required=False,
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input', 'id': 'enablePasswordCheck'})
    )
    password = forms.CharField(
        label="Access Password",
        required=False,
        widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'Set password to open this link'})
    )
    expiration_hours = forms.IntegerField(
        label="Expiration (Hours)",
        required=False,
        initial=24,
        min_value=1,
        max_value=720,
        widget=forms.NumberInput(attrs={'class': 'form-control', 'placeholder': '24'})
    )
    max_downloads = forms.IntegerField(
        label="Maximum Allowed Downloads",
        required=False,
        min_value=1,
        max_value=1000,
        widget=forms.NumberInput(attrs={'class': 'form-control', 'placeholder': 'e.g. 5 (Leave blank for unlimited)'})
    )

    def clean(self):
        cleaned_data = super().clean()
        enable_pw = cleaned_data.get('enable_password')
        pw = cleaned_data.get('password')
        if enable_pw and not pw:
            self.add_error('password', "Please specify a password when password protection is enabled.")
        return cleaned_data


class AccessLinkForm(forms.Form):
    password = forms.CharField(
        label="Link Password",
        widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'Enter required access password'})
    )
