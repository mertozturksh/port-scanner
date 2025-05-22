import socket
import struct
import random

class PacketBuilder:
    @staticmethod
    def checksum(data):
        s = 0
        for i in range(0, len(data) - 1, 2):
            w = (data[i] << 8) + data[i + 1]
            s += w
        if len(data) % 2:
            s += data[-1] << 8
        s = (s >> 16) + (s & 0xffff)
        s += (s >> 16)
        return ~s & 0xffff

    @staticmethod
    def create_ip_header(src_ip, dst_ip):
        version_ihl = (4 << 4) + 5
        tos = 0
        total_length = 40
        identification = random.randint(0, 65535)
        flags_fragment_offset = 0
        ttl = 64
        protocol = socket.IPPROTO_TCP
        checksum_ip = 0

        src_ip_packed = socket.inet_aton(src_ip)
        dst_ip_packed = socket.inet_aton(dst_ip)

        ip_header = struct.pack(
            '!BBHHHBBH4s4s',
            version_ihl,
            tos,
            total_length,
            identification,
            flags_fragment_offset,
            ttl,
            protocol,
            checksum_ip,
            src_ip_packed,
            dst_ip_packed
        )

        checksum_ip = PacketBuilder.checksum(ip_header)
        ip_header = struct.pack(
            '!BBHHHBBH4s4s',
            version_ihl,
            tos,
            total_length,
            identification,
            flags_fragment_offset,
            ttl,
            protocol,
            checksum_ip,
            src_ip_packed,
            dst_ip_packed
        )
        return ip_header

    @staticmethod
    def create_tcp_header(src_ip, dst_ip, src_port, dst_port):
        seq = random.randint(0, 4294967295)
        ack_seq = 0
        offset_res = (5 << 4) + 0
        tcp_flags = 0x02  # SYN
        window = socket.htons(5840)
        checksum_tcp = 0
        urg_ptr = 0

        tcp_header = struct.pack(
            '!HHLLBBHHH',
            src_port,
            dst_port,
            seq,
            ack_seq,
            offset_res,
            tcp_flags,
            window,
            checksum_tcp,
            urg_ptr
        )

        pseudo_header = struct.pack(
            '!4s4sBBH',
            socket.inet_aton(src_ip),
            socket.inet_aton(dst_ip),
            0,
            socket.IPPROTO_TCP,
            len(tcp_header)
        )
        psh = pseudo_header + tcp_header
        checksum_tcp = PacketBuilder.checksum(psh)

        tcp_header = struct.pack(
            '!HHLLBBHHH',
            src_port,
            dst_port,
            seq,
            ack_seq,
            offset_res,
            tcp_flags,
            window,
            checksum_tcp,
            urg_ptr
        )
        return tcp_header 