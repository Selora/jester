__author__ = 'redwind'

import base_driver


class AbstractAttack(object):

    def __init__(self, attack_parameter_list, attack_name):
        if not isinstance(attack_parameter_list, list):
            raise TypeError('Abstract Attack need parameters list')
        self._attack_parameter_list = attack_parameter_list
        self.name = attack_name

    def get_attack_parameters(self):
        return self._attack_parameter_list

    def launch(self):
        raise NotImplementedError('Abstract Method not implemented')

    def print_results(self):
        raise NotImplementedError('Abstract Method not implemented')

    # This is kinda ungly and break the encapsulation, but its a shortcut
    def get_value(self, parameter):
        val = [x.get_value(parameter) for x in self._attack_parameter_list if x.get_value(parameter)][0]
        return val

    def get_driver(self):
        return base_driver.BaseDriver(self)
