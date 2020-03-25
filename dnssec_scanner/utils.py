from __future__ import annotations
from typing import Optional, List, Dict, Set, Tuple
from enum import Enum
from tabulate import tabulate
from textwrap import TextWrapper
from dataclasses import dataclass

import dns
import base64


class Key(Enum):
    KSK = 257
    ZSK = 256


class State(Enum):
    SECURE = 0  # DNSSEC is available
    INSECURE = 1  # there is proof that no DNSSEC is available
    BOGUS = 2  # something is wrong with the chain of trust


@dataclass
class DNSSECScannerResult:
    def __init__(self, domain: str):
        self.domain = domain
        self.state = State.SECURE
        self.note: str = ""
        self.info: List[str] = []
        self.warnings: List[str] = []
        self.errors: List[str] = []

        self.tmp: Dict[bool, List[str]] = {True: [], False: []}

        self.rrsets: List[dns.rrset.RRset] = []

    def add_message(self, error: bool, msg: str):
        self.tmp[error].append(msg)

    def compute_messages(self, warn: bool) -> bool:
        # remove duplicates
        self.info = remove_dup(self.info)
        self.warnings = remove_dup(self.warnings)
        self.errors = remove_dup(self.errors)

        self.info.extend(self.tmp[True])

        if warn and self.tmp[True]:
            self.warnings.extend(self.tmp[False])

        if not self.tmp[True]:
            self.errors.extend(self.tmp[False])

            if self.state == State.SECURE and self.tmp[False]:
                self.state = State.BOGUS

            self.tmp = {True: [], False: []}
            return False

        self.tmp = {True: [], False: []}
        return True

    def append_info(self, msg: str):
        self.info.append(msg)
        self.info = remove_dup(self.info)

    def append_warning(self, msg: str):
        self.warnings.append(msg)
        self.warnings = remove_dup(self.warnings)

    def append_errors(self, msg: str):
        self.errors.append(msg)
        self.errors = remove_dup(self.errors)

    def __str__(self):
        wrapper = TextWrapper(width=40, replace_whitespace=False)
        tmp_info = [wrapper.fill(t) for t in self.info]
        tmp_warn = [wrapper.fill(t) for t in self.warnings]
        tmp_err = [wrapper.fill(t) for t in self.errors]

        res = {"Info": tmp_info, "Warnings": tmp_warn, "Errors": tmp_err}
        return (
            f"\nDomain: {self.domain}, DNSSEC: {self.state}, Note: {self.note}\n\n"
            f"{tabulate(res, headers='keys', tablefmt='fancy_grid', showindex='always')}"
        )


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
        self.RR: Optional[dns.rrset.RRset] = None
        self.child_name: str = ""

    def __str__(self):
        return f"{self.name} @{self.ip}"


def dns_query(domain: str, ip: str, type: int) -> dns.message.Message:
    request = dns.message.make_query(domain, type, want_dnssec=True, payload=16384)
    return dns.query.udp(request, ip)


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
) -> List[Tuple[str, dns.rrset.RRset]]:
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


def remove_dup(l: List[any]) -> List[any]:
    r = []
    for i in l:
        if i not in r:
            r.append(i)
    return r


def nsec3_next_to_string(nsec3: dns.rdtypes.ANY.NSEC3):
    b32_to_b32hex = str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", "0123456789ABCDEFGHIJKLMNOPQRSTUV"
    )
    return base64.b32encode(nsec3.next).decode("utf-8").translate(b32_to_b32hex)


def nsec_window_to_array(nsec: Optional[dns.rdtypes.ANY.NSEC, dns.rdtypes.ANY.NSEC3]) -> Set[int]:
    rrset_types = []
    for window, bitmap in nsec.windows:
        for i, b in enumerate(bitmap):
            for j in range(8):
                if b & (0x80 >> j):
                    rrset_types.append(window * 256 + i * 8 + j)
                    print(f"Type: {dns.rdatatype.to_text(window * 256 + i * 8 + j)}")

    rrset_types = set(rrset_types)
    return rrset_types
