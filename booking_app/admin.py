from django.contrib import admin
from .models import UserProfile, Service, Booking, AuditLog


@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ['user', 'role', 'created_at']
    list_filter = ['role']


@admin.register(Service)
class ServiceAdmin(admin.ModelAdmin):
    list_display = ['name', 'capacity', 'price', 'is_active']


@admin.register(Booking)
class BookingAdmin(admin.ModelAdmin):
    list_display = ['reference', 'user', 'service', 'booking_date', 'status']
    list_filter = ['status']
    readonly_fields = ['reference']


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ['timestamp', 'user', 'action', 'ip_address', 'success']
    list_filter = ['action', 'success']
    readonly_fields = ['timestamp', 'user', 'action', 'ip_address', 'description', 'success']

    def has_add_permission(self, request):
        return False  # Logs should never be manually added

    def has_delete_permission(self, request, obj=None):
        return False  # Logs should never be deleted
