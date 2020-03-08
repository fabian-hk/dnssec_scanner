from __future__ import annotations
from typing import Optional, List, Dict
from enum import Enum
from tabulate import tabulate
from textwrap import TextWrapper
from dataclasses import dataclass

import dns


class Key(Enum):
    KSK = 257
    ZSK = 256


class State(Enum):
    SECURE = 0  # DNSSEC is available
    INSECURE = 1  # there is proof that no DNSSEC is available
    BOGUS = 2  # something is wrong with the chain of trust


@dataclass
class DNSSECScannerResult:

    rrset: dns.rrset.RRset

    def __init__(self, domain: str):
        self.domain = domain
        self.state = State.SECURE
        self.info: List[str] = []
        self.warnings: List[str] = []
        self.errors: List[str] = []

        self.tmp: Dict[bool, List[str]] = {True: [], False: []}

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

    def __str__(self):
        wrapper = TextWrapper(width=40, replace_whitespace=False)
        tmp_info = [wrapper.fill(t) for t in self.info]
        tmp_warn = [wrapper.fill(t) for t in self.warnings]
        tmp_err = [wrapper.fill(t) for t in self.errors]

        res = {"Info": tmp_info, "Warnings": tmp_warn, "Errors": tmp_err}
        return (
            f"\nDomain: {self.domain}, DNSSEC: {self.state}\n\n"
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
        self.RR: Optional[dns.rrset.RRset] = None
        self.RR_type: str = ""
        self.RR_RRSIG: Optional[dns.rrset.RRset] = None
        self.child_name: str = ""

    def compute(self):
        self.RR_type = dns.rdatatype._by_value[
            self.RR.rdtype if isinstance(self.RR, dns.rrset.RRset) else self.RR
        ]

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
    rrs: List[dns.rrset.RRset], rdtype: dns.rdatatype
) -> List[dns.rdtypes.ANY.RRSIG]:
    result = []
    for rr in rrs:
        if rr.rdtype == dns.rdatatype.RRSIG:
            for sig in rr:
                if sig.type_covered == rdtype:
                    result.append(sig)
    return result


def get_rrs_by_type(
    items: List[dns.rrset.RRset], rdtype: dns.rdatatype
) -> List[dns.rrset.RRset]:
    result = []
    for item in items:
        if item.rdtype == rdtype:
            result.append(item)
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


def algorithm_hash_function(algo: Optional[int, str]) -> str:
    algo_str = algo
    if type(algo) != str:
        algo_str = dns.dnssec._algorithm_by_value[algo]
    if "MD5" in algo_str:
        return "MD5"
    elif "SHA1" in algo_str:
        return "SHA1"
    elif "SHA256" in algo_str:
        return "SHA256"
    elif "SHA386" in algo_str:
        return "SHA386"
    elif "SHA512" in algo_str:
        return "SHA512"
    return ""

def remove_dup(l: List[any]) -> List[any]:
    r = []
    for i in l:
        if i not in r:
            r.append(i)
    return r
