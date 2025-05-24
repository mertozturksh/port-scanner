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

def is_valid_ip(ip):
    try:
        # IP adresini parçalara ayır
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        
        # Her parçanın 0-255 arasında olduğunu kontrol et
        for part in parts:
            if not part.isdigit() or not 0 <= int(part) <= 255:
                return False
        return True
    except:
        return False

def is_valid_port(port):
    try:
        port = int(port)
        return 1 <= port <= 65535
    except:
        return False
    
def parse_ports(port_range_str):
    ports = set()
    for part in port_range_str.split(','):
        part = part.strip()
        if '-' in part:
            start, end = part.split('-')
            if not (is_valid_port(start) and is_valid_port(end)):
                raise ValueError("Port numarası 1-65535 arasında olmalıdır!")
            ports.update(range(int(start), int(end) + 1))
        elif part:
            if not is_valid_port(part):
                raise ValueError("Port numarası 1-65535 arasında olmalıdır!")
            ports.add(int(part))
    return sorted(ports)
    
def get_form_data(form):
    data = {};
    try:
        target_ip = form.get("target_ip", "127.0.0.1").strip()
        if not is_valid_ip(target_ip):
            raise ValueError("Geçersiz IP adresi formatı!")

        port_range = form.get("port_range", "80,443").strip()
        if not port_range:
            raise ValueError("Port aralığı boş olamaz!")

        thread_count = form.get("thread_count", "10").strip()
        try:
            thread_count = int(thread_count)
            if not 1 <= thread_count <= 50:
                raise ValueError("Thread sayısı 1-50 arasında olmalıdır!")
        except ValueError:
            raise ValueError("Thread sayısı geçerli bir sayı olmalıdır!")

        data = {
            "target_ip": target_ip,
            "port_range": parse_ports(port_range),
            "thread_count": thread_count
        }
    except ValueError as e:
        data["error"] = str(e)
    except Exception:
        data["error"] = "Geçersiz girdi formatı. Lütfen kontrol ediniz."
    
    return data
