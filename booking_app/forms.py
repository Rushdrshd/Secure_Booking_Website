"""
forms.py — Secure Booking System
OWASP ASVS V5: All input validated server-side with whitelisting + regex
"""

import re

import os
from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.conf import settings
from .models import Booking, Service, UserProfile


# ─── Shared Validators ──────────────────────────────────────────────────────

def validate_no_script(value):
    """Reject any input containing HTML/script tags (XSS prevention)"""
    pattern = re.compile(r'<[^>]+>', re.IGNORECASE)
    if pattern.search(str(value)):
        raise ValidationError("Input contains invalid characters.")


def validate_safe_text(value):
    """Whitelist: allow only letters, numbers, spaces, basic punctuation"""
    pattern = re.compile(r'^[\w\s\-\.,!?@#()\'\"]+$', re.UNICODE)
    if not pattern.match(str(value)):
        raise ValidationError("Input contains invalid characters.")


def validate_phone(value):
    """Allow only digits, spaces, +, -, ()"""
    if value and not re.match(r'^[\d\s\+\-\(\)]{7,20}$', value):
        raise ValidationError("Enter a valid phone number.")


def validate_file_upload(file):
    """
    File upload security (OWASP ASVS V12):
    - Check extension whitelist
    - Check file size
    """
    if not file:
        return

    # 1. Size check
    if file.size > settings.MAX_UPLOAD_SIZE:
        raise ValidationError("File too large. Maximum size is 5 MB.")

    # 2. Extension whitelist
    ext = os.path.splitext(file.name)[1].lower()
    if ext not in settings.ALLOWED_UPLOAD_EXTENSIONS:
        raise ValidationError(
            "File type not allowed. Allowed types: JPG, PNG, PDF."
        )


# ─── Registration Form ───────────────────────────────────────────────────────

class SecureRegistrationForm(UserCreationForm):
    email = forms.EmailField(required=True, max_length=254)
    phone = forms.CharField(
        max_length=20, required=False,
        validators=[validate_phone]
    )

    class Meta:
        model = User
        fields = ['username', 'email', 'first_name', 'last_name',
                  'password1', 'password2']

    def clean_username(self):
        username = self.cleaned_data.get('username', '')
        # Whitelist: alphanumeric + underscore only
        if not re.match(r'^[\w]{3,30}$', username):
            raise ValidationError(
                "Username must be 3–30 characters: letters, numbers, underscore only."
            )
        if User.objects.filter(username__iexact=username).exists():
            raise ValidationError("That username is already taken.")
        return username

    def clean_email(self):
        email = self.cleaned_data.get('email', '').lower().strip()
        if User.objects.filter(email__iexact=email).exists():
            raise ValidationError("An account with that email already exists.")
        return email

    def clean_first_name(self):
        name = self.cleaned_data.get('first_name', '')
        validate_safe_text(name) if name else None
        return name

    def clean_last_name(self):
        name = self.cleaned_data.get('last_name', '')
        validate_safe_text(name) if name else None
        return name


# ─── Login Form ──────────────────────────────────────────────────────────────

class SecureLoginForm(AuthenticationForm):
    """Extends Django's auth form — CSRF handled by middleware"""
    username = forms.CharField(
        max_length=30,
        widget=forms.TextInput(attrs={'autocomplete': 'username'})
    )
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={'autocomplete': 'current-password'})
    )

    def clean_username(self):
        username = self.cleaned_data.get('username', '').strip()
        # Prevent log injection: strip newlines from username
        username = username.replace('\n', '').replace('\r', '')
        return username


# ─── Booking Form ────────────────────────────────────────────────────────────

class BookingForm(forms.ModelForm):
    class Meta:
        model = Booking
        fields = ['service', 'booking_date', 'booking_time', 'notes', 'attachment']
        widgets = {
            'booking_date': forms.DateInput(attrs={'type': 'date'}),
            'booking_time': forms.TimeInput(attrs={'type': 'time'}),
        }

    def clean_notes(self):
        notes = self.cleaned_data.get('notes', '')
        if notes:
            validate_no_script(notes)
        return notes

    def clean_attachment(self):
        file = self.cleaned_data.get('attachment')
        if file:
            validate_file_upload(file)
        return file

    def clean_booking_date(self):
        from django.utils import timezone
        date = self.cleaned_data.get('booking_date')
        if date and date < timezone.now().date():
            raise ValidationError("Booking date cannot be in the past.")
        return date


# ─── Profile Form ────────────────────────────────────────────────────────────

class UserProfileForm(forms.ModelForm):
    first_name = forms.CharField(max_length=50, required=False,
                                 validators=[validate_safe_text])
    last_name = forms.CharField(max_length=50, required=False,
                                validators=[validate_safe_text])
    email = forms.EmailField(required=True)

    class Meta:
        model = UserProfile
        fields = ['phone', 'avatar']

    def __init__(self, *args, user=None, **kwargs):
        super().__init__(*args, **kwargs)
        if user:
            self.fields['first_name'].initial = user.first_name
            self.fields['last_name'].initial = user.last_name
            self.fields['email'].initial = user.email
        self._user = user

    def clean_phone(self):
        phone = self.cleaned_data.get('phone', '')
        validate_phone(phone) if phone else None
        return phone

    def clean_avatar(self):
        file = self.cleaned_data.get('avatar')
        if file and hasattr(file, 'size'):
            validate_file_upload(file)
        return file

    def clean_email(self):
        email = self.cleaned_data.get('email', '').lower().strip()
        qs = User.objects.filter(email__iexact=email)
        if self._user:
            qs = qs.exclude(pk=self._user.pk)
        if qs.exists():
            raise ValidationError("That email is already in use.")
        return email


# ─── Service Form (Admin only) ───────────────────────────────────────────────

class ServiceForm(forms.ModelForm):
    class Meta:
        model = Service
        fields = ['name', 'description', 'capacity', 'price', 'is_active']

    def clean_name(self):
        name = self.cleaned_data.get('name', '')
        validate_safe_text(name)
        return name

    def clean_description(self):
        desc = self.cleaned_data.get('description', '')
        validate_no_script(desc)
        return desc

    def clean_price(self):
        price = self.cleaned_data.get('price')
        if price is not None and price < 0:
            raise ValidationError("Price cannot be negative.")
        return price
