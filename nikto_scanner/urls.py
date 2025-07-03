from django.urls import path
from . import views

urlpatterns = [
    path('', views.nikto_scan_view, name='nikto_scan'),
]