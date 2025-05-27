import sys
import socket
from utils.port_scanner import PortScanner

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except:
        return "127.0.0.1"

def parse_port_range(port_range_str):
    try:
        ports = set()
        
        for part in port_range_str.split(','):
            part = part.strip()
            if '-' in part:
                start, end = map(int, part.split('-'))
                if start > end:
                    start, end = end, start
                ports.update(range(start, end + 1))
            else:
                ports.add(int(part))
        
        return sorted(list(ports))
    except:
        print("Hata: Port aralığı geçersiz. Örnek formatlar:")
        print("  - Tek port: 80")
        print("  - Aralık: 1-100")
        print("  - Virgülle ayrılmış: 80,443,8080")
        print("  - Karışık: 80,443,8000-8100")
        sys.exit(1)

def group_ports(ports):
    if not ports:
        return []
    
    ports = sorted(ports)
    groups = []
    start = ports[0]
    prev = ports[0]
    
    for port in ports[1:]:
        if port != prev + 1:
            if start == prev:
                groups.append(str(start))
            else:
                groups.append(f"{start}-{prev}")
            start = port
        prev = port
    
    if start == prev:
        groups.append(str(start))
    else:
        groups.append(f"{start}-{prev}")
    
    return groups

def create_table(headers, rows):
    col_widths = [len(str(header)) for header in headers]
    for row in rows:
        for i, cell in enumerate(row):
            col_widths[i] = max(col_widths[i], len(str(cell)))
    
    def create_line():
        return "+" + "+".join("-" * (width + 2) for width in col_widths) + "+"
    
    def format_cell(content, width):
        return f" {str(content):<{width}} "
    
    table = []
    table.append(create_line())
    
    header_row = "|" + "|".join(format_cell(header, width) for header, width in zip(headers, col_widths)) + "|"
    table.append(header_row)
    table.append(create_line())
    
    for row in rows:
        data_row = "|" + "|".join(format_cell(cell, width) for cell, width in zip(row, col_widths)) + "|"
        table.append(data_row)
    
    table.append(create_line())
    return "\n".join(table)

def main():
    print("=== Port Tarayıcı Konsol Uygulaması ===")
    
    target_ip = input("Hedef IP adresi: ").strip()
    if not target_ip:
        print("Hata: Hedef IP adresi gerekli!")
        sys.exit(1)

    source_ip = input(f"Kaynak IP adresi (varsayılan: {get_local_ip()}): ").strip()
    if not source_ip:
        source_ip = get_local_ip()

    port_range_str = input("Port aralığı (örn: 80,443,8000-8100): ").strip()
    port_range = parse_port_range(port_range_str)

    print("\nTarama başlatılıyor...")
    print(f"Hedef: {target_ip}")
    print(f"Port aralığı: {port_range_str}")
    print(f"Thread sayısı: 10")
    print("-" * 50)

    scanner = PortScanner(
        target_ip=target_ip,
        source_ip=source_ip,
        port_range=port_range,
        thread_count=10,
        use_threads=True
    )

    results = scanner.scan()

    print("\nTarama Sonuçları:")
    print("-" * 50)
    
    if results['error']:
        print(f"Hata: {results['error']}")
        sys.exit(1)

    system_info = [
        ["İşletim Sistemi Tahmini", results['os_guess']],
        #["İlk TTL Değeri", results['first_ttl']],
        #["İlk Window Size", results['first_window']],
        ["Tarama Süresi", f"{results['scan_time']} saniye"]
    ]
    print("\nSistem Bilgileri:")
    print(create_table(["Özellik", "Değer"], system_info))

    open_ports = []
    closed_ports = []
    no_response = []

    for port, (status, ttl, window) in sorted(results['results'].items()):
        if status == 'OPEN':
            open_ports.append(port)
        elif status == 'CLOSED':
            closed_ports.append(port)
        else:
            no_response.append(port)

    port_status = [
        ["Açık Portlar", len(open_ports), ", ".join(group_ports(open_ports)) or "Yok"],
        ["Kapalı Portlar", len(closed_ports), ", ".join(group_ports(closed_ports)) or "Yok"],
        ["Yanıt Vermeyen Portlar", len(no_response), ", ".join(group_ports(no_response)) or "Yok"]
    ]
    print("\nPort Durumları:")
    print(create_table(["Durum", "Sayı", "Portlar"], port_status))

    # Açık portların detaylı bilgilerini göster
    if open_ports:
        print("\nAçık Port Detayları:")
        port_details = []
        for port in sorted(open_ports):
            status, ttl, window, service = results['results'][port]
            port_details.append([port, service or "Bilinmiyor"])
        print(create_table(["Port", "Servis"], port_details))

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nTarama kullanıcı tarafından durduruldu.")
        sys.exit(0)
    except Exception as e:
        print(f"\nBeklenmeyen bir hata oluştu: {str(e)}")
        sys.exit(1)
