import socket
import struct
import os
import time
import sys
import select
import argparse

ICMP_ECHO = 8
ICMP_ECHO_REPLY = 0
ICMP_TIME_EXCEEDED = 11

def calculate_checksum(packet):
    countTo = (len(packet) // 2) * 2

    count = 0
    sum = 0

    while count < countTo:
        if sys.byteorder == "little":
            loByte = packet[count]
            hiByte = packet[count + 1]
        else:
            loByte = packet[count + 1]
            hiByte = packet[count]
        sum = sum + (hiByte * 256 + loByte)
        count += 2

    if countTo < len(packet):
        sum += packet[count]

    sum = (sum >> 16) + (sum & 0xffff)  # adding the higher order 16 bits and lower order 16 bits
    sum += (sum >> 16)
    answer = ~sum & 0xffff
    answer = socket.htons(answer)

    return answer


def is_valid_ip(hostname):
    ip_parts = hostname.strip().split('.')
    if len(ip_parts) != 4:
        return False

    for part in ip_parts:
        try:
            if int(part) < 0 or int(part) > 255:
                return False
        except ValueError:
            return False

    return True


def to_ip(hostname):
    if is_valid_ip(hostname):
        return hostname
    return socket.gethostbyname(hostname)


class Traceroute:
    def __init__(self, destination_server, packet_size=52, max_hops=64, timeout=1000):
        self.destination_server = destination_server
        self.count_of_packets = 1
        self.packet_size = packet_size
        self.max_hops = max_hops
        self.timeout = timeout
        self.identifier = os.getpid() & 0xffff
        self.seq_no = 0
        self.delays = []
        self.prev_sender_hostname = ""
        self.result = []
        self.unknown_host = False

        self.ttl = 1
        try:
            self.destination_ip = to_ip(destination_server)
        except socket.gaierror:
            self.unknown_host = True

    def print_trace(self, delay, ip_header):

        ip = socket.inet_ntoa(struct.pack('!I', ip_header['Source_IP']))
        try:
            sender_hostname = socket.gethostbyaddr(ip)[0]
        except socket.herror:
            sender_hostname = ip

        if self.prev_sender_hostname != sender_hostname:
            res = {
                "host": sender_hostname,
                "ip": ip,
                "delay": '{:.1f}ms'.format(delay),
                "timeout": False
            }
            self.result.append(res)
            self.prev_sender_hostname = sender_hostname

        if self.seq_no == self.count_of_packets:
            self.prev_sender_hostname = ""

    def header_to_dict(self, keys, packet, struct_format):
        values = struct.unpack(struct_format, packet)
        return dict(zip(keys, values))

    def start_traceroute(self):
        if self.unknown_host:
            return "traceroute: Unknown host {}".format(self.destination_server)

        icmp_header = None
        while self.ttl <= self.max_hops:
            self.seq_no = 0
            try:
                for i in range(self.count_of_packets):
                    icmp_header = self.tracer()
                    if icmp_header != None:
                        if icmp_header.get('error'):
                            return icmp_header.get('message')

            except KeyboardInterrupt:  # handles Ctrl+C
                break

            self.ttl += 1
            if icmp_header is not None:
                if icmp_header['type'] == ICMP_ECHO_REPLY:
                    return self.result

    def tracer(self):
        try:
            icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("ICMP"))
            icmp_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, self.ttl)

        except socket.error as err:
            if err.errno == 1:
                return {
                    "error": True,
                    "message": "Operation not permitted: ICMP messages can only be sent from a process running as root"
                }
            else:
                return {
                    "error": True,
                    "message": "Error: {}".format(err)
                }

        self.seq_no += 1

        sent_time = self.send_icmp_echo(icmp_socket)

        if type(sent_time) == dict:
            if sent_time.get('error'):
                return sent_time

        receive_time, icmp_header, ip_header = self.receive_icmp_reply(icmp_socket)

        icmp_socket.close()
        if receive_time:
            delay = (receive_time - sent_time) * 1000.0
            self.print_trace(delay, ip_header)

        return icmp_header

    def send_icmp_echo(self, icmp_socket):

        header = struct.pack("!BBHHH", ICMP_ECHO, 0, 0, self.identifier, self.seq_no)

        start_value = 65
        payload = []
        for i in range(start_value, start_value+self.packet_size):
            payload.append(i & 0xff)

        data = bytes(payload)
        checksum = calculate_checksum(header + data)
        header = struct.pack("!BBHHH", ICMP_ECHO, 0, checksum, self.identifier, self.seq_no)

        packet = header + data

        send_time = time.time()
        try:
            icmp_socket.sendto(packet, (self.destination_server, 1))

        except socket.error as err:
            icmp_socket.close()
            return {
                "error": True,
                "message": ("General error: %s", err)
            }

        return send_time

    def receive_icmp_reply(self, icmp_socket):
        timeout = self.timeout / 1000

        while True:
            inputReady, _, _ = select.select([icmp_socket], [], [], timeout)
            receive_time = time.time()

            if not inputReady:  # timeout
                res = {
                    "host": None,
                    "ip": None,
                    "delay": None,
                    "timeout": True
                }
                self.result.append(res)
                return None, None, None

            packet_data, address = icmp_socket.recvfrom(2048)

            icmp_keys = ['type', 'code', 'checksum', 'identifier', 'sequence number']
            icmp_header = self.header_to_dict(icmp_keys, packet_data[20:28], "!BBHHH")

            ip_keys = ['VersionIHL', 'Type_of_Service', 'Total_Length', 'Identification', 'Flags_FragOffset', 'TTL',
                       'Protocol', 'Header_Checksum', 'Source_IP', 'Destination_IP']

            ip_header = self.header_to_dict(ip_keys, packet_data[:20], "!BBHHHBBHII")

            return receive_time, icmp_header, ip_header