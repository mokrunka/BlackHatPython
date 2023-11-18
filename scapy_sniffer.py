import ipaddress
from ipaddress import *
from scapy.all import *
from scapy.layers.inet import IP, UDP, TCP, ICMP
import threading
import os


SUBNET = '192.168.10.0/24'
MESSAGE = '^_^'
HOSTS = []


def udp_sender():
    # blasts udp packets into the network to solicit responses
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
        print(f'Sending UDP packets to {SUBNET}...')
        for ip in ipaddress.ip_network(SUBNET).hosts():
            # send our test message out to port 65212 on the destination
            sender.sendto(bytes(MESSAGE, 'utf8'), (str(ip), 65212))


def packet_callback(packet):
    # print(packet.show())
    # print(packet.summary())
    # this prints the command that could be used to generate the response packets in scapy (for reference)
    # print(packet.command())
    # type 3 / code 3 means destination and port unreachable, but indicates a host is likely up
    if packet[ICMP].type == 3 and packet[ICMP].code == 3:
        if packet[IP].src not in HOSTS:
            HOSTS.append(packet[IP].src)
    print(f'Currently discovered hosts: {HOSTS}')


def main(target_ip):
    while True:
        # filter for packets we want to sniff (others will be ignored)
        p_filter = f'(dst {target_ip} or src {target_ip}) and icmp'
        # pack is a list of packets
        pack = sniff(filter=p_filter, prn=packet_callback, count=len(list(ip_network(SUBNET).hosts())))
        # for p in pack:
            # print(p.sniffed_on)


if __name__ == "__main__":
    if len(sys.argv) == 2:
        # note first arg is the filename itself
        target = sys.argv[1]
    else:
        target = '192.168.10.85'
    t = threading.Thread(target=udp_sender)
    t.start()
    main(target)
