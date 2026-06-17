"""booking_app/urls.py"""
from django.urls import path
from . import views

urlpatterns = [
    path('', views.dashboard_view, name='dashboard'),
    path('register/', views.register_view, name='register'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),

    # Bookings — UUID used (no sequential IDs → prevents IDOR)
    path('dashboard/', views.dashboard_view, name='dashboard'),
    path('bookings/new/', views.booking_create, name='booking_create'),
    path('bookings/<uuid:ref>/', views.booking_detail, name='booking_detail'),
    path('bookings/<uuid:ref>/edit/', views.booking_edit, name='booking_edit'),
    path('bookings/<uuid:ref>/cancel/', views.booking_cancel, name='booking_cancel'),
    path('bookings/<uuid:ref>/download/', views.download_attachment, name='download_attachment'),

    # Profile
    path('profile/', views.profile_view, name='profile'),

    # Admin
    path('admin-panel/audit-log/', views.audit_log_view, name='audit_log'),
    path('admin-panel/services/new/', views.service_create, name='service_create'),
    path('admin-panel/services/<int:pk>/edit/', views.service_edit, name='service_edit'),
    path('admin-panel/bookings/', views.manage_bookings, name='manage_bookings'),
    path('admin-panel/bookings/<uuid:ref>/status/', views.update_booking_status, name='update_booking_status'),
]
