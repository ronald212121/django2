from django.urls import path
from . import views

urlpatterns = [
    path('', views.scan_history_view, name='scan_history'),
    path('result/<int:scan_id>/', views.scan_result_view, name='scan_result'),
    path('delete/<int:scan_id>/', views.delete_scan_result, name='delete_scan'),
    path('clear/', views.clear_all_history, name='clear_history'),
    path('export-pdf/<int:scan_id>/', views.export_recommendation_pdf, name='export_recommendation_pdf'),
]