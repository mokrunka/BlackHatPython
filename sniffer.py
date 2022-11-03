import ipaddress
import os
import socket
import struct
import sys
import threading
import time

# target subnet
SUBNET = '192.168.20.0/24'
# a message for the UDP packet to send
MESSAGE = 'ATESTMESSAGE'


def udp_sender():
    # blasts udp packets into the network to solicit responses
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
        for ip in ipaddress.ip_network(SUBNET).hosts():
            print(f'sending a test message to {ip}')
            sender.sendto(bytes(MESSAGE, 'utf8'), (str(ip), 65212))


class IP:
    def __init__(self, buff=None):
        header = struct.unpack('<BBHHHBBH4s4s', buff)
        self.ver = header[0] >> 4
        self.ihl = header[0] & 0xF
        self.tos = header[1]
        self.len = header[2]
        self.id = header[3]
        self.offset = header[4]
        self.ttl = header[5]
        self.protocol_num = header[6]
        self.sum = header[7]
        self.src = header[8]
        self.dst = header[9]

        # make IP addrs human readable
        self.src_address = ipaddress.ip_address(self.src)
        self.dst_address = ipaddress.ip_address(self.dst)

        # the protocol_num is actually a code for the protocol name
        self.protocol_name = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}

        # try to provide the human version of the protocol, otherwise just give the code
        try:
            self.protocol = self.protocol_name[self.protocol_num]
        except Exception as error:
            self.protocol = self.protocol_num
            print(f'Protocol is unrecognized, try googling "IP protocol {self.protocol_num}"')


class ICMP:
    def __init__(self, buff):
        header = struct.unpack('<BBHHH', buff)
        self.type = header[0]
        self.code = header[1]
        self.checksum = header[2]
        self.ident = header[3]
        self.seq_num = header[4]


class Scanner:
    def __init__(self, host):
        self.host = host
        # create raw socket, bind to public interface
        # if windows:
        if os.name == 'nt':
            socket_protocol = socket.IPPROTO_IP
        # if linux/mac:
        else:
            socket_protocol = socket.IPPROTO_ICMP
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
        self.socket.bind((host, 0))
        # socket options, include header
        self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        # enable promiscuous mode for windows
        if os.name == 'nt':
            self.socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    def sniff(self):
        # set of all hosts that are up (respond to our ICMP message)
        hosts_up = set([f'{str(self.host)} *'])
        try:
            while True:
                # read a packet
                raw_buffer = self.socket.recvfrom(65535)[0]
                # create IP header from the first 20 bytes
                ip_header = IP(raw_buffer[0:20])
                # if the protocol is ICMP, do some additional things
                if ip_header.protocol == 'ICMP':
                    # calculate where the ICMP packet starts
                    offset = ip_header.ihl * 4
                    buf = raw_buffer[offset:offset + 8]
                    # create ICMP structure
                    icmp_header = ICMP(buf)
                    if icmp_header.type == 3 & icmp_header.code == 3:
                        # don't have to print this, but it's nice to see what's happening under the hood
                        print(f'Protocol: {ip_header.protocol}, Source: {ip_header.src_address}, Destination: {ip_header.dst_address}')
                        print(f'ICMP Header Type: {icmp_header.type}, ICMP Header Code: {icmp_header.code}')
                        if ipaddress.ip_address(ip_header.src_address) in ipaddress.IPv4Network(SUBNET):
                            # make sure the packet has our test message
                            if raw_buffer[len(raw_buffer) - len(MESSAGE):] == bytes(MESSAGE, 'utf8'):
                                tgt = str(ip_header.src_address)
                                if tgt != self.host and tgt not in hosts_up:
                                    hosts_up.add(str(ip_header.src_address))
                                    print(f'Host Up: {tgt}')

        except KeyboardInterrupt:
            print(f'Exiting, and disabling promiscuous mode.')
            # turn off promiscuous mode on windows
            if os.name == 'nt':
                self.socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            print(f'User interrupted.')
            # if there are entries in hosts_up
            if hosts_up:
                print(f'The following hosts are up: {hosts_up}')


if __name__ == '__main__':
    if len(sys.argv) == 2:
        host = sys.argv[1]
    else:
        host = '192.168.10.85'
    s = Scanner(host)
    time.sleep(5)
    t = threading.Thread(target=udp_sender)
    t.start()
    s.sniff()

