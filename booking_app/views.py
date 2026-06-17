"""
views.py — Secure Booking System
OWASP controls: RBAC, IDOR prevention, no stack traces, audit logging
"""

import logging
import uuid
import os
from functools import wraps

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, logout, authenticate, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib import messages
from django.http import HttpResponseForbidden, Http404, FileResponse
from django.views.decorators.http import require_http_methods, require_POST
from django.views.decorators.cache import never_cache
from django.utils.decorators import method_decorator
from django.db import transaction
from django.conf import settings

from .models import Booking, Service, UserProfile, AuditLog
from .forms import (SecureRegistrationForm, SecureLoginForm, BookingForm,
                    UserProfileForm, ServiceForm)

logger = logging.getLogger('booking_app.security')


# ─── Helpers ─────────────────────────────────────────────────────────────────

def get_client_ip(request):
    """Extract real IP from request (proxy-aware)"""
    x_forwarded = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded:
        return x_forwarded.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR', '0.0.0.0')


def log_action(user, action, request, description, success=True):
    """Write to AuditLog — never log passwords or tokens"""
    AuditLog.objects.create(
        user=user,
        action=action,
        ip_address=get_client_ip(request),
        description=description,
        success=success,
    )


def admin_required(view_func):
    """Decorator: only admin role may access this view"""
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect(settings.LOGIN_URL)
        try:
            if not request.user.profile.is_admin():
                log_action(request.user, 'ACCESS_DENIED', request,
                           f"Non-admin tried to access {request.path}", success=False)
                return render(request, 'booking_app/403.html', status=403)
        except UserProfile.DoesNotExist:
            return render(request, 'booking_app/403.html', status=403)
        return view_func(request, *args, **kwargs)
    return wrapper


def rename_upload(filename):
    """Rename uploaded file to UUID to prevent path traversal / overwrite"""
    ext = os.path.splitext(filename)[1].lower()
    return f"{uuid.uuid4()}{ext}"


# ─── Auth Views ──────────────────────────────────────────────────────────────

@never_cache
@require_http_methods(["GET", "POST"])
def register_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard')

    form = SecureRegistrationForm(request.POST or None)
    if request.method == 'POST':
        if form.is_valid():
            with transaction.atomic():
                user = form.save()
                UserProfile.objects.create(user=user, role='user',
                                           phone=form.cleaned_data.get('phone', ''))
                log_action(user, 'REGISTER', request,
                           f"New user registered: {user.username}")
            messages.success(request, "Account created. Please log in.")
            return redirect('login')
        else:
            logger.warning(f"Failed registration attempt from {get_client_ip(request)}")

    return render(request, 'booking_app/register.html', {'form': form})


@never_cache
@require_http_methods(["GET", "POST"])
def login_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard')

    form = SecureLoginForm(request, data=request.POST or None)
    if request.method == 'POST':
        if form.is_valid():
            user = form.get_user()
            login(request, user)
            log_action(user, 'LOGIN_SUCCESS', request, f"User logged in: {user.username}")
            # Prevent session fixation: Django regenerates session on login
            return redirect('dashboard')
        else:
            ip = get_client_ip(request)
            username = request.POST.get('username', '')
            # Log failed attempt WITHOUT logging the password
            logger.warning(f"Failed login for '{username}' from {ip}")
            log_action(None, 'LOGIN_FAIL', request,
                       f"Failed login attempt for username: {username}", success=False)
            messages.error(request, "Invalid username or password.")

    return render(request, 'booking_app/login.html', {'form': form})


@login_required
@require_POST
def logout_view(request):
    log_action(request.user, 'LOGOUT', request, f"User logged out: {request.user.username}")
    logout(request)
    return redirect('login')


# ─── Dashboard ───────────────────────────────────────────────────────────────

@login_required
@never_cache
def dashboard_view(request):
    try:
        profile = request.user.profile
    except UserProfile.DoesNotExist:
        profile = UserProfile.objects.create(user=request.user, role='user')

    if profile.is_admin():
        bookings = Booking.objects.select_related('user', 'service').order_by('-created_at')[:20]
        context = {'bookings': bookings, 'is_admin': True}
    else:
        # Normal users see ONLY their own bookings (no IDOR)
        bookings = Booking.objects.filter(user=request.user).select_related('service').order_by('-created_at')
        context = {'bookings': bookings, 'is_admin': False}

    return render(request, 'booking_app/dashboard.html', context)


# ─── Booking CRUD ────────────────────────────────────────────────────────────

@login_required
@require_http_methods(["GET", "POST"])
def booking_create(request):
    form = BookingForm(request.POST or None, request.FILES or None)
    if request.method == 'POST' and form.is_valid():
        booking = form.save(commit=False)
        booking.user = request.user

        # Rename file upload to UUID (security)
        if booking.attachment:
            original_name = booking.attachment.name
            booking.attachment.name = rename_upload(original_name)

        booking.save()
        log_action(request.user, 'BOOKING_CREATE', request,
                   f"Booking created: ref={booking.reference}")
        messages.success(request, f"Booking confirmed! Reference: {booking.reference}")
        return redirect('booking_detail', ref=booking.reference)

    services = Service.objects.filter(is_active=True)
    return render(request, 'booking_app/booking_form.html',
                  {'form': form, 'services': services, 'action': 'Create'})


@login_required
def booking_detail(request, ref):
    """IDOR prevention: only owner or admin can view a booking"""
    try:
        uuid.UUID(str(ref))
    except ValueError:
        raise Http404

    booking = get_object_or_404(Booking, reference=ref)

    # Access control: deny if not owner and not admin
    try:
        is_admin = request.user.profile.is_admin()
    except UserProfile.DoesNotExist:
        is_admin = False

    if booking.user != request.user and not is_admin:
        log_action(request.user, 'ACCESS_DENIED', request,
                   f"Unauthorized booking access attempt: {ref}", success=False)
        return render(request, 'booking_app/403.html', status=403)

    return render(request, 'booking_app/booking_detail.html', {'booking': booking})


@login_required
@require_http_methods(["GET", "POST"])
def booking_edit(request, ref):
    booking = get_object_or_404(Booking, reference=ref)

    # Only owner can edit (admins use admin panel)
    if booking.user != request.user:
        log_action(request.user, 'ACCESS_DENIED', request,
                   f"Unauthorized edit attempt: {ref}", success=False)
        return render(request, 'booking_app/403.html', status=403)

    if booking.status == 'cancelled':
        messages.error(request, "Cannot edit a cancelled booking.")
        return redirect('booking_detail', ref=ref)

    form = BookingForm(request.POST or None, request.FILES or None, instance=booking)
    if request.method == 'POST' and form.is_valid():
        updated = form.save(commit=False)
        if updated.attachment and hasattr(updated.attachment.file, 'read'):
            updated.attachment.name = rename_upload(updated.attachment.name)
        updated.save()
        log_action(request.user, 'BOOKING_UPDATE', request,
                   f"Booking updated: ref={ref}")
        messages.success(request, "Booking updated successfully.")
        return redirect('booking_detail', ref=ref)

    return render(request, 'booking_app/booking_form.html',
                  {'form': form, 'booking': booking, 'action': 'Edit'})


@login_required
@require_POST
def booking_cancel(request, ref):
    booking = get_object_or_404(Booking, reference=ref)
    if booking.user != request.user:
        return render(request, 'booking_app/403.html', status=403)

    booking.status = 'cancelled'
    booking.save(update_fields=['status'])
    log_action(request.user, 'BOOKING_DELETE', request,
               f"Booking cancelled: ref={ref}")
    messages.success(request, "Booking cancelled.")
    return redirect('dashboard')


# ─── Profile ─────────────────────────────────────────────────────────────────

@login_required
@require_http_methods(["GET", "POST"])
def profile_view(request):
    try:
        profile = request.user.profile
    except UserProfile.DoesNotExist:
        profile = UserProfile.objects.create(user=request.user, role='user')

    form = UserProfileForm(
        request.POST or None,
        request.FILES or None,
        instance=profile,
        user=request.user
    )
    if request.method == 'POST' and form.is_valid():
        request.user.first_name = form.cleaned_data['first_name']
        request.user.last_name = form.cleaned_data['last_name']
        request.user.email = form.cleaned_data['email']
        request.user.save()
        if form.cleaned_data.get('avatar'):
            form.instance.avatar.name = rename_upload(form.instance.avatar.name)
        form.save()
        messages.success(request, "Profile updated.")
        return redirect('profile')

    return render(request, 'booking_app/profile.html', {'form': form, 'profile': profile})


# ─── Admin Views ─────────────────────────────────────────────────────────────

@login_required
@admin_required
def audit_log_view(request):
    """Admin-only audit log page"""
    logs = AuditLog.objects.select_related('user').order_by('-timestamp')[:200]
    return render(request, 'booking_app/audit_log.html', {'logs': logs})


@login_required
@admin_required
@require_http_methods(["GET", "POST"])
def service_create(request):
    form = ServiceForm(request.POST or None)
    if request.method == 'POST' and form.is_valid():
        service = form.save(commit=False)
        service.created_by = request.user
        service.save()
        log_action(request.user, 'ADMIN_ACTION', request,
                   f"Admin created service: {service.name}")
        messages.success(request, "Service created.")
        return redirect('dashboard')
    return render(request, 'booking_app/service_form.html', {'form': form})


@login_required
@admin_required
@require_http_methods(["GET", "POST"])
def service_edit(request, pk):
    service = get_object_or_404(Service, pk=pk)
    form = ServiceForm(request.POST or None, instance=service)
    if request.method == 'POST' and form.is_valid():
        form.save()
        log_action(request.user, 'ADMIN_ACTION', request,
                   f"Admin updated service: {service.name}")
        messages.success(request, "Service updated.")
        return redirect('dashboard')
    return render(request, 'booking_app/service_form.html',
                  {'form': form, 'service': service})


@login_required
@admin_required
def manage_bookings(request):
    bookings = Booking.objects.select_related('user', 'service').order_by('-created_at')
    return render(request, 'booking_app/manage_bookings.html', {'bookings': bookings})


@login_required
@admin_required
@require_POST
def update_booking_status(request, ref):
    booking = get_object_or_404(Booking, reference=ref)
    new_status = request.POST.get('status')
    if new_status in ['pending', 'confirmed', 'cancelled']:
        booking.status = new_status
        booking.save(update_fields=['status'])
        log_action(request.user, 'ADMIN_ACTION', request,
                   f"Admin updated booking {ref} status to {new_status}")
        messages.success(request, "Status updated.")
    return redirect('manage_bookings')


# ─── Secure File Download (authorized users only) ────────────────────────────

@login_required
def download_attachment(request, ref):
    """Serve uploaded file only to booking owner or admin"""
    booking = get_object_or_404(Booking, reference=ref)
    try:
        is_admin = request.user.profile.is_admin()
    except UserProfile.DoesNotExist:
        is_admin = False

    if booking.user != request.user and not is_admin:
        return render(request, 'booking_app/403.html', status=403)

    if not booking.attachment:
        raise Http404

    file_path = booking.attachment.path
    if not os.path.exists(file_path):
        raise Http404

    return FileResponse(open(file_path, 'rb'), as_attachment=True)


# ─── Custom Error Pages (no stack traces exposed) ────────────────────────────

def error_400(request, exception=None):
    return render(request, 'booking_app/400.html', status=400)

def error_403(request, exception=None):
    return render(request, 'booking_app/403.html', status=403)

def error_404(request, exception=None):
    return render(request, 'booking_app/404.html', status=404)

def error_500(request):
    return render(request, 'booking_app/500.html', status=500)
