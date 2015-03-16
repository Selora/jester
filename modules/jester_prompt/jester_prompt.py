__author__ = 'redwind'

import modules.base.abstract_attack as abstract_attack
import modules.base.attack_parameters as attack_parameters
import modules.base.base_driver as base_driver

class JesterPrompt:

    def __init__(self, available_attacks):
        if not isinstance(available_attacks, list):
            raise TypeError('JesterPrompt need attack list')
        if len(available_attacks) == 0:
            raise Exception('No available attacks!')
        if not isinstance(available_attacks[0], abstract_attack.AbstractAttack):
            raise TypeError('JesterPrompt need a list of AbstractAttack')

        self._available_attacks = available_attacks
        self._selected_attack = None

    def launch_attack(self):
        driver = self._selected_attack.get_driver()
        driver.launch_attack()

    def print_attack_results(self):
        self._selected_attack.print_results()

    def print_available_attacks(self):
        print('\nAvailable attacks :')
        for index, attack in zip(range(len(self._available_attacks)), self._available_attacks):
            print(str(index) + ': ' + attack.name)

    def select_attack(self, index):
        if index >= len(self._available_attacks):
            raise IndexError('Attack index out of bound')
        self._selected_attack = self._available_attacks[index]

    def print_parameters(self):
        print('\nParameters for attack ' + self._selected_attack.name)
        for attack_parameter in self._selected_attack.get_attack_parameters():
            print('\n' + '\'' + attack_parameter.name + '\'' + ' required parameters:')

            required_parameters = attack_parameter.get_all_required()
            for (key, value) in required_parameters.items():
                print(str(key) + ':\t' + str(value[attack_parameters.attack_parameter_fields.DESCRIPTION]))

            print('\n' + '\'' + attack_parameter.name + '\'' + ' optional parameters:')

            optional_parameters = attack_parameter.get_all_optional()
            for (key, value) in optional_parameters.items():
                print(str(key) + ':\t' + str(value[attack_parameters.attack_parameter_fields.DESCRIPTION]))

    def prompt_parameters(self):
        for attack_parameter in self._selected_attack.get_attack_parameters():
            print('\n' + '\'' + attack_parameter.name + '\'' + ' required parameters:')

            required_parameters = attack_parameter.get_all_required()
            for (key, value) in required_parameters.items():
                entered_value = raw_input(str(key) + ':')
                attack_parameter.set_value(key, entered_value)

            optional_parameters = attack_parameter.get_all_optional()
            if len(optional_parameters) > 0:
                prompt_optional = raw_input('Enter optional parameters as well? (y/n):')
                if prompt_optional == 'y':
                    print('\n' + '\'' + attack_parameter.name + '\'' + ' optional parameters:')


                    for (key, value) in optional_parameters.items():
                        entered_value = raw_input(str(key) + ':')
                        attack_parameter.set_value(key, entered_value)