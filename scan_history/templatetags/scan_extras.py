from django import template
from django.utils.safestring import mark_safe
import json

register = template.Library()

@register.filter
def jsonify(value):
    """
    Filter untuk mengkonversi object ke string JSON
    """
    return mark_safe(json.dumps(value))

@register.filter
def get_item(dictionary, key):
    """
    Filter untuk mengakses item dari dictionary dengan key
    """
    return dictionary.get(key)

@register.filter
def mul(value, arg):
    """
    Filter untuk perkalian
    """
    try:
        return float(value) * float(arg)
    except (ValueError, TypeError):
        return 0

@register.filter
def div(value, arg):
    """
    Filter untuk pembagian dengan penanganan yang lebih baik untuk NaN dan None
    """
    try:
        # Pastikan value dan arg adalah angka
        value = float(value)
        arg = float(arg)
        
        # Periksa apakah arg adalah 0 atau sangat dekat dengan 0
        if arg == 0 or abs(arg) < 1e-9:
            return 0
            
        return value / arg
        
    except (ValueError, TypeError, ZeroDivisionError):
        # Menangani kasus ketika input bukan angka atau pembagian dengan 0
        return 0

@register.filter
def safe_div(value, arg):
    """
    Filter untuk pembagian yang aman, mengembalikan 0 jika ada masalah
    """
    try:
        # Pastikan value dan arg adalah angka
        value = float(value)
        arg = float(arg)
        
        # Periksa apakah arg adalah 0 atau sangat dekat dengan 0
        if arg == 0 or abs(arg) < 1e-9:
            return 0
            
        return value / arg
        
    except (ValueError, TypeError, ZeroDivisionError):
        # Menangani kasus ketika input bukan angka atau pembagian dengan 0
        return 0