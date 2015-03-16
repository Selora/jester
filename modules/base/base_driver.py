__author__ = 'redwind'

import abstract_attack
import attack_parameters

class BaseDriver:

    def __init__(self, attack):
        if not isinstance(attack, abstract_attack.AbstractAttack):
            raise TypeError('Attack is not of type AbstractAttack')

        self.attack = attack

    def is_all_required_parameters_set(self):
        for attack_parameter in self.attack.get_attack_parameters():
            required_parameters = attack_parameter.get_all_required()
            for (key, value) in required_parameters.items():
                if not value:
                    return False

        return True

    def launch_attack(self):
        if not self.is_all_required_parameters_set():
            print('ERROR : Cannot launch attack, missing required parameter')
            return

        self.pre_attack()

        print('Launching attack ' + self.attack.name)
        self.attack.launch()

    def pre_attack(self):
        pass