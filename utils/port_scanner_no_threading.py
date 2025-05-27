import socket
import struct
import random
import time
from .packet_builder import PacketBuilder

class PortScannerNoThreading:
    def __init__(self, target_ip, source_ip, port_range, socket_timeout=3, idle_timeout=6):
        self.target_ip = target_ip
        self.source_ip = source_ip
        self.port_range = port_range
        self.socket_timeout = socket_timeout
        self.idle_timeout = idle_timeout
        self.first_ttl = None
        self.first_window = None
        self.responses = {}
        self.expected_ports = []
        self.error = None

    def send_syn(self, dst_port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            src_port = random.randint(1024, 65535)

            ip_header = PacketBuilder.create_ip_header(self.source_ip, self.target_ip)
            tcp_header = PacketBuilder.create_tcp_header(self.source_ip, self.target_ip, src_port, dst_port)
            packet = ip_header + tcp_header

            s.sendto(packet, (self.target_ip, 0))
            self.expected_ports.append(dst_port)
            s.close()
        except PermissionError:
            self.error = "Raw socket kullanımı için uygulamayı yönetici (admin/root) olarak çalıştırmalısınız."
            return

    def listen(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            s.settimeout(self.socket_timeout)
            
            start_time = time.time()
            while True:
                try:
                    data, addr = s.recvfrom(65535)
                    ip_header = data[0:20]
                    tcp_header = data[20:40]

                    ip_hdr = struct.unpack('!BBHHHBBH4s4s', ip_header)
                    tcp_hdr = struct.unpack('!HHLLBBHHH', tcp_header)

                    src_ip = socket.inet_ntoa(ip_hdr[8])
                    src_port = tcp_hdr[0]
                    flags = tcp_hdr[5]
                    ttl = ip_hdr[5]
                    window = tcp_hdr[6]

                    if src_ip == self.target_ip and src_port in self.port_range and src_port not in self.responses:
                        # SYN+ACK kontrolü (0x12 = 00010010)
                        if (flags & 0x3F) == 0x12:
                            if self.first_ttl is None and self.first_window is None:
                                self.first_ttl = ttl
                                self.first_window = window
                            self.responses[src_port] = ('OPEN', ttl, window)
                        # RST+ACK kontrolü (0x14 = 00010100)
                        elif (flags & 0x3F) == 0x14:
                            self.responses[src_port] = ('CLOSED', ttl, window)
                except socket.timeout:
                    if len(self.responses) == len(self.expected_ports):
                        break
                    if time.time() - start_time > self.idle_timeout and len(self.responses) > 0:
                        break
                    continue
        except PermissionError:
            self.error = "Raw socket kullanımı için uygulamayı yönetici (admin/root) olarak çalıştırmalısınız."
        finally:
            s.close()

    @staticmethod
    def os_guess(ttl):
        if ttl is None:
            return "Bilinmiyor"
        elif 240 <= ttl <= 255:
            return "Cisco/Unix-like"
        elif 117 <= ttl <= 128:
            return "Windows"
        elif 61 <= ttl <= 64:
            return "Linux/macOS"
        else:
            return "Bilinmiyor"

    def run(self):
        for port in self.port_range:
            self.send_syn(port)
            time.sleep(0.001)
        
        self.listen()

        for port in self.expected_ports:
            if port not in self.responses:
                self.responses[port] = ('NO RESPONSE', None, None)

    @staticmethod
    def get_service_name(port):
        try:
            return socket.getservbyport(port)
        except:
            return "Bilinmiyor"

    def scan(self):
        start_time = time.time()
        self.run()
        scan_time = time.time() - start_time
        os_guess = self.os_guess(self.first_ttl)
        
        results_with_services = {}
        for port, (status, ttl, window) in self.responses.items():
            service = self.get_service_name(port) if status == 'OPEN' else None
            results_with_services[port] = (status, ttl, window, service)
            
        return {
            'results': results_with_services,
            'os_guess': os_guess,
            'scan_time': round(scan_time, 2),
            'first_ttl': self.first_ttl,
            'first_window': self.first_window,
            'error': self.error
        } 