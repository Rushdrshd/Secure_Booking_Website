"""
models.py — Secure Booking System
All queries use Django ORM (no raw SQL) → injection-free
"""

import uuid
from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone


class UserProfile(models.Model):
    """Extended user profile with role (RBAC)"""
    ROLE_CHOICES = [
        ('admin', 'Admin'),
        ('user', 'Normal User'),
    ]
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='user')
    phone = models.CharField(max_length=20, blank=True)
    # Profile picture stored outside web root with UUID filename
    avatar = models.ImageField(upload_to='avatars/', blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} ({self.role})"

    def is_admin(self):
        return self.role == 'admin'


class Service(models.Model):
    """Bookable services (admin manages these)"""
    name = models.CharField(max_length=100)
    description = models.TextField(max_length=1000)
    capacity = models.PositiveIntegerField(default=1)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    is_active = models.BooleanField(default=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name


class Booking(models.Model):
    """Booking records — CRUD module"""
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('confirmed', 'Confirmed'),
        ('cancelled', 'Cancelled'),
    ]
    # UUID prevents IDOR (Insecure Direct Object Reference)
    reference = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='bookings')
    service = models.ForeignKey(Service, on_delete=models.CASCADE)
    booking_date = models.DateField()
    booking_time = models.TimeField()
    notes = models.TextField(max_length=500, blank=True)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending')
    # Uploaded attachment (e.g. ID/document)
    attachment = models.FileField(upload_to='attachments/', blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Booking {self.reference} — {self.user.username}"


class AuditLog(models.Model):
    """
    Security audit log (OWASP ASVS V7)
    Logs: login, logout, failed login, admin actions, suspicious activity
    NEVER logs passwords, tokens, or sensitive data
    """
    ACTION_CHOICES = [
        ('LOGIN_SUCCESS', 'Login Success'),
        ('LOGIN_FAIL', 'Login Failed'),
        ('LOGOUT', 'Logout'),
        ('REGISTER', 'User Registered'),
        ('BOOKING_CREATE', 'Booking Created'),
        ('BOOKING_UPDATE', 'Booking Updated'),
        ('BOOKING_DELETE', 'Booking Deleted'),
        ('ADMIN_ACTION', 'Admin Action'),
        ('ACCESS_DENIED', 'Access Denied'),
        ('FILE_UPLOAD', 'File Uploaded'),
        ('PASSWORD_CHANGE', 'Password Changed'),
    ]
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    action = models.CharField(max_length=30, choices=ACTION_CHOICES)
    # IP stored for security monitoring; no passwords/tokens ever stored
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    description = models.TextField(max_length=500)
    timestamp = models.DateTimeField(default=timezone.now)
    success = models.BooleanField(default=True)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f"[{self.timestamp}] {self.action} — {self.user}"
