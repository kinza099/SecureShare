import os
from django import forms
from django.core.exceptions import ValidationError
from .models import FileRecord
from encryption.validator import validate_uploaded_file

class FileUploadForm(forms.Form):
    file = forms.FileField(
        label="Select File",
        widget=forms.ClearableFileInput(attrs={'class': 'form-control', 'id': 'file-input-field'})
    )
    display_name = forms.CharField(
        label="Display Name (Optional)",
        required=False,
        max_length=255,
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'e.g. Confidential Project Report'})
    )

    def clean_file(self):
        uploaded_file = self.cleaned_data.get('file')
        if not uploaded_file:
            raise ValidationError("Please select a file to upload.")
        validate_uploaded_file(uploaded_file)
        return uploaded_file


class FileVersionUploadForm(forms.Form):
    file = forms.FileField(
        label="Select New Version File",
        widget=forms.ClearableFileInput(attrs={'class': 'form-control'})
    )
    change_summary = forms.CharField(
        label="Summary of Changes",
        required=False,
        max_length=255,
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'e.g. Added section 3.2 on network firewall'})
    )

    def clean_file(self):
        uploaded_file = self.cleaned_data.get('file')
        if not uploaded_file:
            raise ValidationError("Please select a file to upload.")
        validate_uploaded_file(uploaded_file)
        return uploaded_file


class FileRenameForm(forms.ModelForm):
    class Meta:
        model = FileRecord
        fields = ['display_name']
        widgets = {
            'display_name': forms.TextInput(attrs={'class': 'form-control'}),
        }
