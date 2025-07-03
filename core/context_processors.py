def navigation(request):
    """
    Context processor untuk menentukan item navigasi aktif
    """
    path = request.path.strip('/')
    
    # Default active state
    nav_active = {
        'home': False,
        'nmap': False,
        'nikto': False,
        'history': False,
        'about': False,
        'contact': False,
    }
    
    # Set active based on path
    if path == '':
        nav_active['home'] = True
    elif path.startswith('nmap'):
        nav_active['nmap'] = True
    elif path.startswith('nikto'):
        nav_active['nikto'] = True
    elif path.startswith('history'):
        nav_active['history'] = True
    elif path.startswith('about'):
        nav_active['about'] = True
    elif path.startswith('contact'):
        nav_active['contact'] = True
    
    return {'nav_active': nav_active}