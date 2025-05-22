import socket
import struct
import random
import threading
import queue
import time
from .packet_builder import PacketBuilder

class PortScanner:
    def __init__(self, target_ip, source_ip, port_range, timeout, thread_count, use_threads):
        self.target_ip = target_ip
        self.source_ip = source_ip
        self.port_range = port_range
        self.timeout = timeout
        self.thread_count = min(thread_count, 50)  # Thread sayısını sınırla
        self.use_threads = use_threads
        self.first_ttl = None
        self.first_window = None
        self.port_queue = queue.Queue()
        self.responses = {}
        self.expected_ports = []
        self.error = None
        self.stop_event = threading.Event()

    def send_syn(self, dst_port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            src_port = random.randint(1024, 65535)

            ip_header = PacketBuilder.create_ip_header(self.source_ip, self.target_ip)
            tcp_header = PacketBuilder.create_tcp_header(self.source_ip, self.target_ip, src_port, dst_port)
            packet = ip_header + tcp_header

            s.sendto(packet, (self.target_ip, 0))
            self.expected_ports.append(dst_port)
            s.close()  # Socket'i hemen kapat
        except PermissionError:
            self.error = "Raw socket kullanımı için uygulamayı yönetici (admin/root) olarak çalıştırmalısınız."
            self.stop_event.set()
            return

    def listen(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            s.settimeout(self.timeout)
            
            start_time = time.time()
            while not self.stop_event.is_set() and (time.time() - start_time) < self.timeout:
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
                        if flags & 0x12:  # SYN + ACK
                            if self.first_ttl is None and self.first_window is None:
                                self.first_ttl = ttl
                                self.first_window = window
                            self.responses[src_port] = ('OPEN', ttl, window)
                        elif flags & 0x14:  # RST + ACK
                            self.responses[src_port] = ('CLOSED', ttl, window)
                except socket.timeout:
                    continue
        except PermissionError:
            self.error = "Raw socket kullanımı için uygulamayı yönetici (admin/root) olarak çalıştırmalısınız."
            self.stop_event.set()
        finally:
            s.close()

    @staticmethod
    def os_guess(ttl):
        if ttl is None:
            return "Bilinmiyor"
        if ttl <= 64:
            return "Linux/Unix"
        elif ttl <= 128:
            return "Windows"
        elif ttl <= 255:
            return "Router / Network Device"
        else:
            return "Unknown"

    def worker(self):
        while not self.port_queue.empty() and not self.stop_event.is_set():
            try:
                port = self.port_queue.get_nowait()
                self.send_syn(port)
                time.sleep(0.001)  # Çok kısa bir bekleme
            except queue.Empty:
                break
            except Exception as e:
                self.error = f"Worker hatası: {str(e)}"
                self.stop_event.set()
                break

    def run(self):
        # Port kuyruğunu doldur
        for p in self.port_range:
            self.port_queue.put(p)

        # Dinleyici thread'i başlat
        listener = threading.Thread(target=self.listen)
        listener.daemon = True
        listener.start()

        # Worker thread'leri başlat
        if self.use_threads:
            threads = []
            for _ in range(self.thread_count):
                t = threading.Thread(target=self.worker)
                t.daemon = True
                t.start()
                threads.append(t)

            # Worker thread'lerin bitmesini bekle
            for t in threads:
                t.join(timeout=self.timeout)

        # Tüm portlar için yanıt alındıysa veya timeout olduysa dinleyiciyi durdur
        while not self.stop_event.is_set():
            if len(self.responses) == len(self.expected_ports):
                self.stop_event.set()
                break
            time.sleep(0.1)  # CPU kullanımını azaltmak için kısa bekleme

        # Dinleyici thread'in bitmesini bekle
        listener.join(timeout=1)  # 1 saniye yeterli

        # Eksik portları işaretle
        for port in self.expected_ports:
            if port not in self.responses:
                self.responses[port] = ('NO RESPONSE', None, None)

    def scan(self):
        start_time = time.time()
        self.run()
        scan_time = time.time() - start_time
        os_guess = self.os_guess(self.first_ttl)
        return {
            'results': self.responses,
            'os_guess': os_guess,
            'scan_time': round(scan_time, 2),
            'first_ttl': self.first_ttl,
            'first_window': self.first_window,
            'error': self.error
        } 