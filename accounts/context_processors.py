import socket

def get_lan_ip():
    """
    Attempt to find the host's actual local IPv4 address connected to LAN/Wi-Fi.
    Falls back to 127.0.0.1 if no active network interface exists.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Does not actually send data, just routes to default gateway
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    except Exception:
        try:
            ip = socket.gethostbyname(socket.gethostname())
        except Exception:
            ip = '127.0.0.1'
    finally:
        s.close()
    return ip

def lan_info(request):
    """
    Context processor providing LAN connection details for templates,
    QR codes, and system dashboard indicators.
    """
    host_ip = get_lan_ip()
    port = request.get_port() or '8000'
    base_url = f"{request.scheme}://{host_ip}:{port}"
    
    return {
        'LAN_HOST_IP': host_ip,
        'LAN_HOST_PORT': port,
        'LAN_BASE_URL': base_url,
        'CURRENT_USER': request.user if request.user.is_authenticated else None,
        'IS_ADMIN': request.user.is_authenticated and (request.user.is_admin or request.user.is_superuser),
    }
