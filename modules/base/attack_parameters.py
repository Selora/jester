__author__ = 'redwind'


def enum(**enums):
        return type('Enum', (), enums)

attack_parameter_type = enum(REQUIRED=0, OPTIONAL=1)
#UPDATE THE LENGTH IF YOU ADD SOMETHING!
attack_parameter_fields = enum(TYPE=0, VALUE=1, DESCRIPTION=2, FIELD_LENGTH=3)

class AttackParameters(object):

    def __init__(self, name):
        self._parameters = {}
        self.name = name

    def get_value(self, parameter):
        return None if not self._parameters.get(parameter) \
            else self._parameters.get(parameter)[attack_parameter_fields.VALUE]

    def get_param_with_type(self, parameter_type):
        return {key: value for (key, value) in self._parameters.items()
                if value[attack_parameter_fields.TYPE] == parameter_type}

    def get_all_required(self):
        return self.get_param_with_type(attack_parameter_type.REQUIRED)

    def get_all_optional(self):
            return self.get_param_with_type(attack_parameter_type.OPTIONAL)

    def set_required(self, parameter, description):
        self._parameters[parameter] = [None] * attack_parameter_fields.FIELD_LENGTH
        self._parameters[parameter][attack_parameter_fields.TYPE] = attack_parameter_type.REQUIRED
        self._parameters[parameter][attack_parameter_fields.DESCRIPTION] = description

    def set_optional(self, parameter, description):
        self._parameters[parameter] = [None] * attack_parameter_fields.FIELD_LENGTH
        self._parameters[parameter][attack_parameter_fields.TYPE] = attack_parameter_type.OPTIONAL
        self._parameters[parameter][attack_parameter_fields.DESCRIPTION] = description

    def set_value(self, parameter, value):
        if not self._parameters[parameter]:
            raise Exception('Parameter type not set')

        self._parameters[parameter][attack_parameter_fields.VALUE] = value