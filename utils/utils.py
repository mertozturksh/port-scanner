import socket

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
        "port_range": parse_ports(form.get("port_range", "80,443").strip()),
        "thread_count": int(form.get("thread_count", "50").strip()),
    }
    return data
