from scapy.all import *
from scapy.layers.inet import IP, UDP, TCP, ICMP
import ipaddress
import threading


SUBNET = '192.168.10.0/24'
MESSAGE = '^_^'
hosts = []


def udp_sender():
    # blasts udp packets into the network to solicit responses
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
        for ip in ipaddress.ip_network(SUBNET).hosts():
            # send our test message out to port 65212 on the destination
            sender.sendto(bytes(MESSAGE, 'utf8'), (str(ip), 65212))


def packet_callback(packet):
    # print(packet.show())
    # print(packet.summary())
    # print(packet.command())
    if packet[ICMP].type == 3 and packet[ICMP].code == 3:
        print(packet.command())
        print(packet[IP].src)


def main(target_ip):
    while True:
        try:
            # filter
            p_filter = f'dst {target_ip} or src {target_ip} and icmp'
            # pack is a list of packets
            pack = sniff(filter=p_filter, prn=packet_callback, count=2)
            for p in pack:
                print(p.sniffed_on)
        except KeyboardInterrupt:
            break
        finally:
            host_discovery_list(pack)


def host_discovery_list(pack):
    for p in pack:
        if p[IP].src not in hosts:
            hosts.append(p[IP].src)
    print(hosts)


if __name__ == "__main__":
    if len(sys.argv) == 2:
        target = sys.argv[1]
    else:
        target = '192.168.10.85'
    t = threading.Thread(target=udp_sender)
    t.start()
    main(target)
