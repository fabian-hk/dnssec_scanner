from __future__ import annotations
from typing import Optional, List, Tuple
from enum import Enum
from dataclasses import dataclass

from tabulate import tabulate
from textwrap import TextWrapper
import dns
import logging

from .messages import Message

log = logging.getLogger("dnssec_scanner")


class Key(Enum):
    KSK = 257
    ZSK = 256


class State(Enum):
    SECURE = 0  # DNSSEC is available
    INSECURE = 1  # there is proof that no DNSSEC is available
    BOGUS = 2  # something is wrong with the chain of trust


@dataclass
class DNSSECScannerResult:
    def __init__(self, domain: str, requested_type: int):
        self.domain = domain
        self.qname = domain
        self.requested_type = requested_type
        self.state = State.SECURE
        self.note: str = ""
        self.logs: List[str] = []
        self.warnings: List[str] = []
        self.errors: List[str] = []

        self.secure_rrsets: List[dns.rrset.RRset] = []
        self.insecure_rrsets: List[dns.rrset.RRset] = []
        self.requested_rrset: Tuple[bool, Optional[dns.rrset.RRset]] = (False, None)

    def compute_message(self, new_msg: Message) -> bool:
        if new_msg:
            # everything okay
            self.logs.append(str(new_msg))
            self.warnings.extend([str(msg) for msg in new_msg.warnings])
            return True
        else:
            # something went wrong
            if new_msg.message:
                self.errors.append(str(new_msg))
            self.errors.extend([str(msg) for msg in new_msg.warnings])
            return False

    def change_state(self, success: bool):
        if not success and self.state == State.SECURE:
            self.state = State.BOGUS

    def compute_batch(self, msgs: List[Message]) -> bool:
        success = False
        for msg in msgs:
            success |= bool(msg)

        for msg in msgs:
            if success:
                if msg:
                    self.logs.append(str(msg))
                self.warnings.extend([str(m) for m in msg.warnings])
            else:
                if msg.message:
                    self.errors.append(str(msg))
                self.errors.extend([str(m) for m in msg.warnings])

        return success

    def compute_requested_type(self, type: int):
        for rr in self.secure_rrsets:
            if rr.rdtype == type:
                self.requested_rrset = (True, rr)
                return

        for rr in self.insecure_rrsets:
            if rr.rdtype == type:
                self.requested_rrset = (False, rr)
                return

    def __str__(self):
        width = 80
        wrapper = TextWrapper(width=width, replace_whitespace=False)
        tmp_info = (
            [wrapper.fill(t) for t in self.logs] if self.logs else ["Execution failed"]
        )
        tmp_warn = (
            [wrapper.fill(t) for t in self.warnings]
            if self.warnings
            else ["All good ;)"]
        )
        tmp_err = (
            [wrapper.fill(t) for t in self.errors] if self.errors else ["All good ;)"]
        )

        logs = {expand_string("Log", width): tmp_info}
        warnings = {expand_string("Warnings", width): tmp_warn}
        errors = {expand_string("Errors", width): tmp_err}

        output = (
            f"\n{tabulate(logs, headers='keys', tablefmt='fancy_grid', showindex='always')}\n"
            f"{tabulate(warnings, headers='keys', tablefmt='fancy_grid', showindex='always')}\n"
            f"{tabulate(errors, headers='keys', tablefmt='fancy_grid', showindex='always')}\n"
            f"\nDomain: {self.qname}, DNSSEC: {self.state}, Note: {self.note}\n"
            f"* not protected\n"
        )
        if self.requested_rrset[1]:
            if self.requested_rrset[0]:
                output += f"\nResult for requested type (secured):\n{self.requested_rrset[1].to_text()}"
            else:
                output += f"\nResult for requested type (not secured):\n{self.requested_rrset[1].to_text()}"
        elif self.requested_type:
            output += f"\nCould not find a RR set for the requested type {dns.rdatatype.to_text(self.requested_type)}"
        return output


class Zone:
    def __init__(self, name: str, ip: str, domain: str, parent: Optional[Zone]):
        self.name = name
        self.ip = ip
        self.domain = domain
        self.parent: Zone = parent
        self.DNSKEY: Optional[dns.rrset.RRset] = None
        self.DNSKEY_RRSIG: Optional[dns.rrset.RRset] = None
        self.trusted_DS: List[dns.rrset.RRset] = []
        self.untrusted_DS: List[dns.rrset.RRset] = []
        self.RR: Optional[List[dns.rrset.RRset]] = None
        self.child_name: str = ""

    def __str__(self):
        return f"{self.name} @{self.ip}"


class SoaState(Enum):
    FOUND = 0
    FOUND_CNAME = 1
    NOT_FOUND = 2


def dns_query(
        domain: str, ip: str, type: int, tries: Optional[int] = 0
) -> dns.message.Message:
    try:
        request = dns.message.make_query(domain, type, want_dnssec=True, payload=32768)
        return dns.query.udp(request, ip, timeout=5)
    except dns.exception.Timeout as e:
        log.debug("Query timeout")
        if tries < 10:
            return dns_query(domain, ip, type, tries + 1)
        else:
            raise e
    except dns.message.Truncated as e:
        log.debug("Truncated flag was set - trying again with TCP")
        return dns_query_tcp(domain, ip, type)


def dns_query_tcp(
        domain: str, ip: str, type: int, tries: Optional[int] = 0
) -> dns.message.Message:
    try:
        request = dns.message.make_query(domain, type, want_dnssec=True, payload=32768)
        return dns.query.tcp(request, ip, timeout=5)
    except dns.exception.Timeout as e:
        log.debug("Query timeout")
        if tries < 5:
            return dns_query(domain, ip, type, tries + 1)
        else:
            raise e


def get_rr_by_type(
        items: List[dns.rrset.RRset], rdtype: dns.rdatatype
) -> Optional[dns.rrset.RRset]:
    for item in items:
        if item.rdtype == rdtype:
            return item
    return None


def get_rrsig_for_rr(
        rrs: List[dns.rrset.RRset], rr: dns.rrset.RRset
) -> List[dns.rdtypes.ANY.RRSIG]:
    result = []
    for t in rrs:
        if t.rdtype == dns.rdatatype.RRSIG and rr.name == t.name:
            for sig in t:
                if sig.type_covered == rr.rdtype:
                    result.append(sig)
    return result


def get_rrs_by_type(
        items: List[dns.rrset.RRset], rdtype: dns.rdatatype
) -> List[Tuple[str, dns.rrset.RRset]]:
    result = []
    for item in items:
        if item.rdtype == rdtype:
            result.append((item.name, item))
    return result


def get_dnskey(keys: dns.rrset.RRset, k: Key) -> List[dns.rdtypes.ANY.DNSKEY]:
    result = []
    if isinstance(keys, dns.rrset.RRset):
        for key in keys:
            if key.flags == k.value:
                result.append(key)
    return result


def get_rrsig(rrsigs: dns.rrset.RRset, key):
    for rrsig in rrsigs:
        if rrsig.key_tag == dns.dnssec.key_id(key):
            return rrsig
    return None


def get_ds_by_dnskey(
        rrsets: List[dns.rrset.RRset], ksk: dns.rdtypes.ANY.DNSKEY
) -> List[Tuple[str, dns.rdtypes.ANY.DS]]:
    key_tag = dns.dnssec.key_id(ksk)
    result = []
    for rrset in rrsets:
        if rrset.rdtype == dns.rdatatype.DS:
            for ds in rrset.items:
                if ds.key_tag == key_tag:
                    result.append((str(rrset.name), ds))
    return result


def digest_algorithm(algo: int) -> str:
    """
    Source: https://tools.ietf.org/html/rfc4509#section-5
    :param algo:
    :return:
    """
    if algo == 1:
        return "SHA1"
    elif algo == 2:
        return "SHA256"
    return ""


def expand_string(s: str, width: int) -> str:
    l = width - len(s)
    for _ in range(l):
        s += " "
    return s


def remove_duplicates(list_var: List[any]) -> List[any]:
    result = []
    for el in list_var:
        if el not in result:
            result.append(el)

    return result
