# FIXED: core/views.py - UNIVERSAL Core Views tanpa infinite loop

from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib.auth import logout
from django.contrib import messages
from django.contrib.auth.models import User
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.core.cache import cache
from django.utils import timezone
from .models import UserProfile, ScanHistory, ScanResult
from .forms import UserProfileForm
import json
import logging

logger = logging.getLogger(__name__)

def home_view(request):
    """
    FIXED: Homepage tanpa infinite loop calculations
    """
    if not request.user.is_authenticated:
        return redirect('account_login')
    
    # FIXED: Use cached statistics untuk performance
    cache_key = f"user_stats_{request.user.id}"
    cached_stats = cache.get(cache_key)
    
    if cached_stats:
        context = {
            'user': request.user,
            **cached_stats
        }
    else:
        # Calculate stats efficiently
        stats = calculate_user_stats_efficiently(request.user)
        
        # Cache for 5 minutes
        cache.set(cache_key, stats, 300)
        
        context = {
            'user': request.user,
            **stats
        }
    
    return render(request, 'core/home.html', context)

@login_required
def dashboard_view(request):
    """
    FIXED: Dashboard tanpa redundant calculations
    """
    # FIXED: Use cached data untuk dashboard
    cache_key = f"dashboard_{request.user.id}"
    cached_dashboard = cache.get(cache_key)
    
    if cached_dashboard:
        context = {
            'user': request.user,
            **cached_dashboard
        }
    else:
        # Calculate dashboard data efficiently
        dashboard_data = calculate_dashboard_data_efficiently(request.user)
        
        # Cache for 10 minutes
        cache.set(cache_key, dashboard_data, 600)
        
        context = {
            'user': request.user,
            **dashboard_data
        }
    
    return render(request, 'core/dashboard.html', context)

@login_required
def profile_view(request):
    """
    FIXED: Profile view dengan efficient stats calculation
    """
    profile, created = UserProfile.objects.get_or_create(user=request.user)
    
    # Handle form submission
    if request.method == 'POST':
        form = UserProfileForm(request.POST, request.FILES, instance=profile)
        if form.is_valid():
            form.save()
            messages.success(request, 'Profile berhasil diupdate!')
            return redirect('profile')
    else:
        form = UserProfileForm(instance=profile)
    
    # FIXED: Update profile stats efficiently SEKALI SAJA
    update_profile_stats_efficiently(profile)
    
    context = {
        'form': form,
        'profile': profile,
    }
    return render(request, 'core/profile.html', context)

def calculate_user_stats_efficiently(user):
    """
    FIXED: Calculate user stats SEKALI SAJA tanpa infinite loop
    """
    try:
        # Count scans efficiently
        scan_history_count = ScanHistory.objects.filter(user=user).count()
        scan_results_count = ScanResult.objects.filter(user=user).count()
        total_scans = scan_history_count + scan_results_count
        
        # Count vulnerabilities efficiently
        total_vulnerabilities = 0
        
        # From ScanResult - use direct database query
        scan_results = ScanResult.objects.filter(user=user).values(
            'critical_count', 'high_count', 'medium_count', 'low_count'
        )
        for scan in scan_results:
            total_vulnerabilities += (
                scan['critical_count'] + scan['high_count'] + 
                scan['medium_count'] + scan['low_count']
            )
        
        # From ScanHistory
        scan_history_vulns = ScanHistory.objects.filter(user=user).aggregate(
            total=models.Sum('vulnerabilities_count')
        )['total'] or 0
        total_vulnerabilities += scan_history_vulns
        
        # Get recent scans efficiently
        recent_scan_history = list(ScanHistory.objects.filter(user=user).order_by('-created_at')[:3])
        recent_scan_results = list(ScanResult.objects.filter(user=user).order_by('-created_at')[:3])
        
        # Combine and sort
        all_recent_scans = recent_scan_history + recent_scan_results
        all_recent_scans.sort(key=lambda x: x.created_at, reverse=True)
        recent_scans = all_recent_scans[:5]
        
        return {
            'total_scans': total_scans,
            'recent_scans': recent_scans,
            'total_vulnerabilities': total_vulnerabilities,
            'scan_history_count': scan_history_count,
            'scan_results_count': scan_results_count,
        }
        
    except Exception as e:
        logger.error(f"Error calculating user stats: {e}")
        return {
            'total_scans': 0,
            'recent_scans': [],
            'total_vulnerabilities': 0,
            'scan_history_count': 0,
            'scan_results_count': 0,
        }

def calculate_dashboard_data_efficiently(user):
    """
    FIXED: Calculate dashboard data SEKALI SAJA
    """
    try:
        # Get user scans efficiently
        user_scan_history = ScanHistory.objects.filter(user=user)
        user_scan_results = ScanResult.objects.filter(user=user)
        
        # Count totals
        total_scans = user_scan_history.count() + user_scan_results.count()
        completed_scans = user_scan_history.filter(is_completed=True).count() + user_scan_results.count()
        
        # Count vulnerabilities efficiently
        vulnerabilities_found = 0
        
        # From ScanResult
        scan_results_vulns = user_scan_results.aggregate(
            total_critical=models.Sum('critical_count'),
            total_high=models.Sum('high_count'),
            total_medium=models.Sum('medium_count'),
            total_low=models.Sum('low_count'),
        )
        vulnerabilities_found += sum(v or 0 for v in scan_results_vulns.values())
        
        # From ScanHistory
        scan_history_vulns = user_scan_history.aggregate(
            total=models.Sum('vulnerabilities_count')
        )['total'] or 0
        vulnerabilities_found += scan_history_vulns
        
        # Get recent scans efficiently
        recent_history = list(user_scan_history.order_by('-created_at')[:5])
        recent_results = list(user_scan_results.order_by('-created_at')[:5])
        all_recent = recent_history + recent_results
        all_recent.sort(key=lambda x: x.created_at, reverse=True)
        recent_scans = all_recent[:10]
        
        return {
            'total_scans': total_scans,
            'completed_scans': completed_scans,
            'vulnerabilities_found': vulnerabilities_found,
            'recent_scans': recent_scans,
        }
        
    except Exception as e:
        logger.error(f"Error calculating dashboard data: {e}")
        return {
            'total_scans': 0,
            'completed_scans': 0,
            'vulnerabilities_found': 0,
            'recent_scans': [],
        }

def update_profile_stats_efficiently(profile):
    """
    FIXED: Update profile stats SEKALI SAJA tanpa infinite loop
    """
    try:
        user = profile.user
        
        # Count scans efficiently
        scan_history_count = ScanHistory.objects.filter(user=user).count()
        scan_results_count = ScanResult.objects.filter(user=user).count()
        total_scans = scan_history_count + scan_results_count
        
        # Count vulnerabilities efficiently
        total_vulnerabilities = 0
        
        # From ScanResult - use aggregate
        scan_results_vulns = ScanResult.objects.filter(user=user).aggregate(
            total_critical=models.Sum('critical_count'),
            total_high=models.Sum('high_count'),
            total_medium=models.Sum('medium_count'),
            total_low=models.Sum('low_count'),
        )
        total_vulnerabilities += sum(v or 0 for v in scan_results_vulns.values())
        
        # From ScanHistory
        scan_history_vulns = ScanHistory.objects.filter(user=user).aggregate(
            total=models.Sum('vulnerabilities_count')
        )['total'] or 0
        total_vulnerabilities += scan_history_vulns
        
        # Get last scan date efficiently
        latest_scan_history = ScanHistory.objects.filter(user=user).order_by('-created_at').first()
        latest_scan_result = ScanResult.objects.filter(user=user).order_by('-created_at').first()
        
        last_scan_date = None
        if latest_scan_history and latest_scan_result:
            last_scan_date = max(latest_scan_history.created_at, latest_scan_result.created_at)
        elif latest_scan_history:
            last_scan_date = latest_scan_history.created_at
        elif latest_scan_result:
            last_scan_date = latest_scan_result.created_at
        
        # Update profile SEKALI SAJA
        profile.total_scans = total_scans
        profile.vulnerabilities_found = total_vulnerabilities
        if last_scan_date:
            profile.last_scan_date = last_scan_date
        profile.save()
        
        # Clear user stats cache
        cache_key = f"user_stats_{user.id}"
        cache.delete(cache_key)
        
        logger.info(f"Profile stats updated for user {user.username}: {total_scans} scans, {total_vulnerabilities} vulnerabilities")
        
    except Exception as e:
        logger.error(f"Error updating profile stats: {e}")

def custom_logout_view(request):
    """Custom logout view dengan pesan"""
    logout(request)
    messages.success(request, 'Anda telah berhasil logout.')
    return redirect('account_login')

@login_required
@csrf_exempt
def save_scan_result(request):
    """
    FIXED: API endpoint untuk menyimpan hasil scan tanpa infinite loop
    """
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            
            # Simpan ke ScanHistory
            scan_history = ScanHistory.objects.create(
                user=request.user,
                target=data.get('target'),
                scan_type=data.get('scan_type'),
                results=json.dumps(data.get('results', {})),
                vulnerabilities_count=data.get('vulnerabilities_count', 0),
                is_completed=True
            )
            
            # Simpan ke ScanResult
            scan_result = ScanResult.objects.create(
                user=request.user,
                target=data.get('target'),
                tool=data.get('tool', data.get('scan_type')),
                scan_type=data.get('scan_type'),
                result=json.dumps(data.get('results', {})),
                low_count=data.get('low_count', 0),
                medium_count=data.get('medium_count', 0),
                high_count=data.get('high_count', 0),
                critical_count=data.get('critical_count', 0),
                info_count=data.get('info_count', 0),
            )
            
            # FIXED: Update profile stats efficiently
            profile, created = UserProfile.objects.get_or_create(user=request.user)
            update_profile_stats_efficiently(profile)
            
            # Clear caches
            cache.delete(f"user_stats_{request.user.id}")
            cache.delete(f"dashboard_{request.user.id}")
            
            return JsonResponse({
                'status': 'success', 
                'scan_history_id': scan_history.id,
                'scan_result_id': scan_result.id,
                'message': 'Scan results saved successfully'
            })
        except Exception as e:
            logger.error(f"Error saving scan result: {e}")
            return JsonResponse({'status': 'error', 'message': str(e)})
    
    return JsonResponse({'status': 'error', 'message': 'Method not allowed'})

def about_view(request):
    """About page"""
    return render(request, 'core/about.html')

def contact_view(request):
    """Contact page"""
    return render(request, 'core/contact.html')

def sync_user_profile_stats(user):
    """
    FIXED: Utility function untuk sync profile stats SEKALI SAJA
    """
    try:
        profile, created = UserProfile.objects.get_or_create(user=user)
        update_profile_stats_efficiently(profile)
        
        return {
            'total_scans': profile.total_scans,
            'total_vulnerabilities': profile.vulnerabilities_found,
            'last_scan_date': profile.last_scan_date,
            'status': 'success'
        }
        
    except Exception as e:
        logger.error(f"Error syncing profile stats: {e}")
        return {
            'status': 'error',
            'message': str(e)
        }

@login_required
def clear_user_cache(request):
    """
    FIXED: Clear user cache (useful for debugging)
    """
    try:
        cache.delete(f"user_stats_{request.user.id}")
        cache.delete(f"dashboard_{request.user.id}")
        
        messages.success(request, "Cache cleared successfully!")
        return redirect('dashboard')
        
    except Exception as e:
        messages.error(request, f"Error clearing cache: {e}")
        return redirect('dashboard')

# FIXED: Import models for aggregation
from django.db import models