"""config/urls.py"""
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static

handler400 = 'booking_app.views.error_400'
handler403 = 'booking_app.views.error_403'
handler404 = 'booking_app.views.error_404'
handler500 = 'booking_app.views.error_500'

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('booking_app.urls')),
]
