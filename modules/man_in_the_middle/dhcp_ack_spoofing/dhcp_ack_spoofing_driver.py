#!/usr/bin/python2

__author__ = 'redwind'

import modules.base.base_driver as base_driver

import os
from subprocess import PIPE, Popen


class DHCPAckSpoofDriver(base_driver.BaseDriver):

    def pre_attack(self):

        if os.getuid() != 0:
            print('This tools need to be runned as root!')
            exit()

        p = Popen(['sysctl', 'net.ipv4.ip_forward'], stdout=PIPE, stderr=PIPE)
        (out, err) = p.communicate()
        if int(out.split(' ')[2]) != 1:
            print('Packet forwarding is not enabled!')
            activate_forwarding = raw_input('Activate it? (y/n) :')
            if activate_forwarding == 'y':
                p1 = Popen(['sysctl', 'net.ipv4.ip_forward=1'], stdout=PIPE, stderr=PIPE)
                p1.communicate()

        interface = self.attack.get_value('interface')

        p2 = Popen(['sysctl', 'net.ipv4.conf.' + interface + '.send_redirects'], stdout=PIPE, stderr=PIPE)
        (out, err) = p2.communicate()
        if int(out.split(' ')[2]) != 0:
            print('By default, this interface will send ICMP_REDIRECT to redirect victim to the real gateway.')
            print('That means you won\'t be able to intercept packets!')
            print('If you are only targetting the DNS hack, however, this should not cause problem.')

            activate_forwarding = raw_input('Deactivate ICMP redirect? (y/n) :')
            if activate_forwarding == 'y':
                p3 = Popen(['sysctl', 'net.ipv4.conf.'+interface+'.send_redirects=0'], stdout=PIPE, stderr=PIPE)
                p3.communicate()


