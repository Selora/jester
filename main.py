#!/usr/bin/python2

__author__ = 'redwind'

import modules.jester_prompt.jester_prompt as jester_prompt

# available attacks (TODO move into a database of some sort...)
import modules.scanner.dhcp.dhcp_scanner as dhcp_scanner
import modules.man_in_the_middle.dhcp_ack_spoofing.dhcp_ack_spoofing as dhcp_ack_spoofing


def main():
    registered_attacks = [
        dhcp_scanner.DHCPScanner(),
        dhcp_ack_spoofing.DHCPAckSpoofing(),
    ]

    prompt = jester_prompt.JesterPrompt(registered_attacks)
    prompt.print_available_attacks()
    index = raw_input('\nPlease select an attack :')
    prompt.select_attack(int(index))
    prompt.print_parameters()
    print('\nPlease enter required parameters value')
    prompt.prompt_parameters()

    prompt.launch_attack()

    print('Attack finished!')
    prompt.print_attack_results()

if __name__ == "__main__":
    main()
