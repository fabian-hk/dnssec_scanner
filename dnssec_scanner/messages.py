from __future__ import annotations
from typing import List, Optional

import dns

from dnssec_scanner import utils


class Validator:
    DS = "DS"
    UNTRUSTED_DS = "untrusted DS"
    KSK = "KSK"
    UNTRUSTED_KSK = "untrusted KSK"
    ZSK = "ZSK"


class Msg:
    RRSIG_NOT_FOUND = ", RRSIG not found"
    DS_NOT_FOUND = ", DS not found"
    NOT_FOUND = " not found"
    VALIDATED = " validated"
    VALIDATION_FAILURE = " validation failed"


class Types:
    KSK = "KSK"
    ZSK = "ZSK"


class Message:
    def __init__(
            self,
            zone_name: str,
            owner_name: str,
            rdtype: Optional[int, str] = "",
            rr: Optional[dns.rrset.RRset] = None,
            type_id: Optional[str, int] = ""
    ):
        self.validated = False

        self.zone_name = zone_name
        self.owner_name = owner_name

        self.type_name = rdtype
        self.type_id = ""
        if isinstance(rdtype, int):
            self.type_name = dns.rdatatype.to_text(rdtype)
            self.type_id = self.get_type_ids(rdtype, rr)

        if type_id:
            self.type_id = type_id

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

    def add_warning(
            self,
            validator: str,
            validator_id: Optional[int, str],
            msg: str,
            rr: Optional[dns.rrset.RRset] = None,
    ):
        warn_msg = Message(self.zone_name, self.owner_name, self.type_name, rr)
        warn_msg.validator = validator
        warn_msg.validator_id = validator_id
        warn_msg.message = msg
        self.warnings.append(warn_msg)

    def get_type_ids(self, rdtype: int, rr: Optional[dns.rrset.RRset]) -> str:
        if not rr:
            return ""

        if rdtype == dns.rdatatype.DS:
            return self.get_type_ids_ds(rr)
        elif rdtype == dns.rdatatype.DNSKEY:
            return self.get_type_ids_dnskey(rr)

        return ""

    def get_type_ids_ds(self, rr: dns.rrset.RRset) -> str:
        description = [str(i.key_tag) for i in rr.items]
        return ",".join(description)

    def get_type_ids_dnskey(self, rr: dns.rrset.RRset) -> str:
        description = [str(dns.dnssec.key_id(key)) for key in rr]
        return ",".join(description)

    def __str__(self):
        zone_name = f"{self.zone_name} zone:"
        owner_name = ""
        type_name = f" {self.type_name}"
        message = f" record{self.message}"
        validator = f""

        if self.owner_name:
            owner_name = f" {self.owner_name}"

        if self.type_id:
            type_name = f"{type_name} {self.type_id}"

        if self.validator:
            validator = f", using {self.validator} {self.validator_id}"

        return f"{zone_name}{owner_name}{type_name}{message}{validator}"

    def __bool__(self):
        return self.validated
