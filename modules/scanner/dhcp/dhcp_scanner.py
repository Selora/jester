__author__ = 'redwind'

import modules.base.abstract_attack as abstract_attack
import modules.base.attack_parameters as attack_parameters
import modules.utils.table_printer as table_printer

import random

import scapy.layers as layers
import scapy.arch as arch
import scapy.utils as utils

from scapy.all import *
from scapy.sendrecv import *


class DHCPScanner(abstract_attack.AbstractAttack):

    def __init__(self):

        self.misc_param = attack_parameters.AttackParameters('misc')
        self.misc_param.set_required('interface', 'The network interface to use (eth0, wlp3s0, etc..)')
        self.misc_param.set_required('response_sniff_timeout', 'The time to wait for DHCP servers '
                                                               'after DISCOVER is sent (5 is good)')

        self.dhcp_server_list = []

        super(DHCPScanner, self).__init__([self.misc_param], 'dhcp_scanner')

    def launch(self):

        # Forge a dhcp_discover packet, send it and wait for DHCP servers to show up
        dhcp_discover_packet = self._build_dhcp_discover()
        dhcp_offer_packets = self._get_dhcp_response_packets(dhcp_discover_packet)

        self._extract_dhcp_info(dhcp_offer_packets)

    def print_results(self):
        if len(self.dhcp_server_list) == 0:
            print('No DHCP server found!')
            return

        for index, dhcp in zip(range(len(self.dhcp_server_list)), self.dhcp_server_list):
            print('\n---------DHCP server ' + str(index) + '---------')
            for (key, value) in dhcp.items():
                print(str(key) + ':\t\t\t' + str(value))

    def _get_dhcp_response_packets(self, dhcp_discover_packet):
        sendp(
            dhcp_discover_packet,
            iface=self.get_value('interface'),
            verbose=0
        )

        sniffed_packets = sniff(
            timeout=int(self.get_value('response_sniff_timeout')),
            filter='udp',
            iface=self.get_value('interface')
            )

        return [x for x in sniffed_packets
                if layers.dhcp.DHCP in x
                and x[layers.dhcp.DHCP].options[0][0] == 'message-type'
                and x[layers.dhcp.DHCP].options[0][1] == 2]  # DHCP OFFER == 2

    def _extract_dhcp_info(self, dhcp_offer_packets):
        self.dhcp_server_list = []
        for dhcp_offer in dhcp_offer_packets:
            dhcp_server = {}
            dhcp_server['MAC'] = dhcp_offer[layers.l2.Ether].src

            options_list = dhcp_offer[layers.dhcp.DHCP].options

            # Get the IP of the DHCP server requested by client
            dhcp_server['server_id'] = next((x for x in options_list if x[0] == 'server_id'),
                                            (None, None))[1]

            dhcp_server['gateway'] = next((x for x in options_list if x[0] == 'router'),
                                            (None, None))[1]

            dhcp_server['nameserver'] = next((x for x in options_list if x[0] == 'name_server'),
                                            (None, None))[1]

            dhcp_server['broadcast'] = next((x for x in options_list if x[0] == 'broadcast_address'),
                                            (None, None))[1]

            dhcp_server['netmask'] = next((x for x in options_list if x[0] == 'subnet_mask'),
                                            (None, None))[1]

            dhcp_server['domain_name'] = next((x for x in options_list if x[0] == 'domain'),
                                            (None, None))[1]

            dhcp_server['lease_time'] = next((x for x in options_list if x[0] == 'lease_time'),
                                            (None, 43200))[1]

            self.dhcp_server_list += [dhcp_server]


    def _build_dhcp_discover(self):
        # Set mac address to the NIC card or a spoofed one
        hw = arch.get_if_hwaddr(self.get_value('interface'))

        return  layers.l2.Ether(dst='ff:ff:ff:ff:ff:ff', src=hw)/\
                layers.inet.IP(src='0.0.0.0', dst='255.255.255.255', id=0)/\
                layers.inet.UDP(sport=68, dport=67)/\
                layers.dhcp.BOOTP(op='BOOTREQUEST', xid=random.randrange(2000, 0xFFFFFF), chaddr=utils.mac2str(hw))/\
                layers.dhcp.DHCP(options=[
                    ('message-type', 1),
                    'end']
                    )
