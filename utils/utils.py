import socket
import re

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip

def is_valid_ip(ip):
    try:
        socket.inet_aton(ip)
        # Ayrıca IPv4 formatı için regex ile kontrol
        if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', ip):
            return all(0 <= int(part) <= 255 for part in ip.split('.'))
        return False
    except Exception:
        return False

def is_valid_ports(port_range_str):
    # Sadece rakam, virgül ve tire olmalı
    if not re.match(r'^[0-9,\- ]+$', port_range_str):
        return False
    try:
        for part in port_range_str.split(','):
            part = part.strip()
            if not part:
                continue
            if '-' in part:
                start, end = part.split('-')
                if not (0 <= int(start) <= 65535 and 0 <= int(end) <= 65535 and int(start) <= int(end)):
                    return False
            else:
                if not (0 <= int(part) <= 65535):
                    return False
        return True
    except Exception:
        return False
    
def parse_ports(port_range_str):
    ports = set()
    for part in port_range_str.split(','):
        part = part.strip()
        if '-' in part:
            start, end = part.split('-')
            ports.update(range(int(start), int(end) + 1))
        elif part:
            ports.add(int(part))
    return sorted(ports)
    
def get_form_data(form):
    data = {
        "target_ip": form.get("target_ip", "").strip(),
        "advanced": form.get("advanced") == "1",
        "port_range": parse_ports(form.get("port_range", "").strip()),
        "thread_count": int(form.get("thread_count", "1").strip()),
        "timeout": form.get('timeout', 15),
    }
    if not data["advanced"]:
        data["port_range"] = [80,443]
        data["thread_count"] = 1
    return data

def validate_form_data(form_data):
    if not is_valid_ip(form_data["target_ip"]):
        return "Geçerli bir IP adresi giriniz. (Örn: 192.168.1.1)"
    if not is_valid_ports(form_data["port_range"]):
        return "Geçerli bir port aralığı giriniz. (Örn: 80,443 veya 20-25)"
    return None