from django.urls import path
from . import views

urlpatterns = [
    # URL yang sudah ada - PERTAHANKAN
    path('', views.home_view, name='home'),
    path('about/', views.about_view, name='about'),
    path('contact/', views.contact_view, name='contact'),
    
    # URL UNTUK AUTHENTICATION
    path('dashboard/', views.dashboard_view, name='dashboard'),
    path('profile/', views.profile_view, name='profile'),
    path('logout/', views.custom_logout_view, name='custom_logout'),
    
    # API URL
    path('api/save-scan/', views.save_scan_result, name='save_scan_result'),
]