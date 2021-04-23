import socket
import sys, time
import argparse
from struct import *
import csv


class Sniffer:
    def __init__(self):
        self.ip_count = 0
        self.tcp_count = 0
        self.udp_count = 0
        self.icmp_count = 0
        self.dns_count = 0
        self.start_time = time.time()

        parser = argparse.ArgumentParser(description='Packet Sniffer')
        parser.add_argument("--time", type=int, default=0)
        self.end_time = parser.parse_args()
        self.s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))



    def sniff(self):
        while True:

            packet = self.s.recvfrom(65565)
            packet = packet[0]
            #Size of ethernet header is 14
            ethernet_header = packet[0:14]

            # Unpack ethernet header. Refer to the document for the composition of ethernet header
            eth = unpack('!6s6sH', ethernet_header)

            ethernet_protocol = socket.ntohs(eth[2])


            # IPv4(8) or IPv6(56710). EtherType for IPv4 and IPv6 is 0x0800 and 0x86DD
            if ethernet_protocol == 8 or ethernet_protocol == 56710:
                # Ignore the ethernet header
                packet = packet[14:]

                self.ip_count += 1

                # Size of IP header is 20
                ip_header = packet[0:20]

                # Unpack IP header. Refer to the document for the composition of IP header
                iph = unpack('! 8x B B 2x 4s 4s', ip_header)


                ttl, protocol, src, dest = iph[0], iph[1], iph[2], iph[3]

                # protocol field in the IP header identifies next level protocol

                # TCP
                if protocol == 6:
                    self.tcp_count += 1

                # UDP
                elif protocol == 17:
                    # Ignore the IP header
                    packet = packet[20:]
                    udp_header = packet[:8]
                    self.udp_count += 1
                    udph = unpack('!HHHH' , udp_header)
                    source_port = udph[0]
                    dest_port = udph[1]


                    if source_port == 53 or dest_port == 53:
                        self.dns_count += 1

                # ICMP
                elif protocol == 1:
                    self.icmp_count += 1

                self.time_check()



    def time_check(self):
        if self.end_time.time > 0 and ((time.time() - self.start_time) > self.end_time.time):
            self.output()
            sys.exit(1)


    def output(self):
        res = [
            'IP packets: {}'.format(self.ip_count),
            'TCP Packets: {}'.format(self.tcp_count),
            'UDP Packets: {}'.format(self.udp_count),
            'ICMP Packets: {}'.format(self.icmp_count),
            'DNS Packets: {}'.format(self.dns_count),
        ]
        print('------------------------------------------------------------')
        print(' '.join(res))

    def run(self):
        try:
            self.sniff()
        except KeyboardInterrupt:
            self.output()





if __name__ == '__main__':
    app = Sniffer()
    app.run()
