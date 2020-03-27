from __future__ import annotations
from typing import List, Optional

import dns


class Validator:
    DS = "DS"
    UNTRUSTED_DS = "untrusted DS"
    KSK = "KSK"
    UNTRUSTED_KSK = "untrusted KSK"
    ZSK = "ZSK"


class Msg:
    RRSIG_NOT_FOUND = "RRSIG not found"
    DS_NOT_FOUND = "DS not found"
    NOT_FOUND = "not found"
    VALIDATED = "validated"
    VALIDATION_FAILURE = "validation failed"


class Types:
    KSK = "KSK"
    ZSK = "ZSK"


class Message:
    def __init__(self, zone_name: str, owner_name: str, type: Optional[int, str] = ""):
        self.validated = False

        self.zone_name = zone_name
        self.owner_name = owner_name

        self.type = type
        if isinstance(type, int):
            self.type = dns.rdatatype.to_text(type)

        self.validator: str = ""
        self.validator_id: int = -1

        self.message: str = ""

        self.warnings: List[Message] = []

    def set_success(self, validator: str, validator_id: Optional[int, str]):
        self.validated = True
        self.validator = validator
        self.validator_id = validator_id
        self.message = Msg.VALIDATED

    def set_not_found(self, msg: str):
        self.validated = False
        self.message = msg

    def add_warning(self, validator: str, validator_id: Optional[int, str], msg: str):
        warn_msg = Message(self.zone_name, self.owner_name, self.type)
        warn_msg.validator = validator
        warn_msg.validator_id = validator_id
        warn_msg.message = msg
        self.warnings.append(warn_msg)

    def __str__(self):
        if self.validator:
            s = f"{self.zone_name} zone: {self.owner_name} {self.type} record {self.message}, using {self.validator} {self.validator_id}"
        else:
            s = f"{self.zone_name} zone: {self.owner_name} {self.type} {self.message}"
        return s

    def __bool__(self):
        return self.validated
