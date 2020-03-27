from typing import List


class Validator:
    DS = "DS"
    KSK = "KSK"
    ZSK = "ZSK"


class Msg:
    NOT_FOUND = "RRSIG not found"
    VALIDATED = "validated"
    VALIDATION_FAILURE = "validation failed"


class Message:
    def __init__(self, log: bool, zone_name: str, owner_name: str, type: int):
        self.log = log

        self.zone_name = zone_name
        self.owner_name = owner_name
        self.type = type

        self.validator: str = ""
        self.validator_id: int = -1

        self.message: str = ""

        self.warnings: List[Message] = []

    def set_msg(self, log: bool, validator: str, validator_id: int, msg: str):
        self.log = log
        self.validator = validator
        self.validator_id = validator_id
        self.message = msg

    def add_warning(self, validator: str, validator_id: int, msg: str):
        warn_msg = Message(False, self.zone_name, self.owner_name, self.type)
        warn_msg.validator = validator
        warn_msg.validator_id = validator_id
        warn_msg.msg = msg
        self.warnings.append(warn_msg)

    def __str__(self):
        if self.validator:
            s = f"{self.zone_name}: {self.owner_name} {self.type} record {self.message}, with {self.validator} {self.validator_id}"
        else:
            s = f"{self.zone_name}: {self.owner_name} {self.type} {self.message}"
        return s
