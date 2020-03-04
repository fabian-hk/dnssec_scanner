from __future__ import annotations
from typing import List, Optional, Tuple
from dataclasses import dataclass

import logging
import dns.name
import dns.query
import dns.dnssec
import dns.message
import dns.resolver
import dns.rdatatype
from enum import Enum

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("dnssec_scanner")


class State(Enum):
    SECURE = 0  # DNSSEC is available
    INSECURE = 1  # there is proof that no DNSSEC is available
    BOGUS = 2  # something is wrong with the chain of trust


class Key(Enum):
    KSK = 257
    ZSK = 256


@dataclass
class DNSSECScannerResult:

    rrset: dns.rrset.RRset

    def __init__(self, domain: str):
        self.domain = domain
        self.state = State.SECURE
        self.warnings: List[str] = []
        self.errors: List[str] = []

    def __str__(self):
        return f"Domain: {self.domain}, DNSSEC: {self.state}"


class Zone:
    name: str
    ip: str
    DNSKEY: dns.rrset.RRset
    DNSKEY_RRSIG: dns.rrset.RRset
    RR: dns.rrset.RRset
    RR_type: str
    RR_RRSIG: dns.rrset.RRset
    parent: Optional[Zone]
    child_name: str = ""

    def __init__(self, name: str, ip: str, parent: Optional[Zone]):
        self.name = name
        self.ip = ip
        self.parent = parent

    def compute(self):
        self.RR_type = dns.rdatatype._by_value[
            self.RR.rdtype if isinstance(self.RR, dns.rrset.RRset) else self.RR
        ]

    def __str__(self):
        return f"{self.name} @{self.ip}"


class DNSSECScanner:

    ROOT_ZONE = "199.7.83.42"
    RESOLVER_IPS = ["8.8.8.8", "8.8.4.4", "1.1.1.1"]

    def __init__(self, domain: str):
        self.domain = domain

    def run_scan(self) -> DNSSECScannerResult:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = self.RESOLVER_IPS

        zone = Zone(".", self.ROOT_ZONE, None)
        result = DNSSECScannerResult(self.domain)

        result = self.scan_zone(zone, result, resolver)

        log.info(f"-------------------------------------")
        for rrset in result.rrset.to_text().split("\n"):
            log.info(f"Result: {rrset}")

        return result

    def scan_zone(
        self, zone: Zone, result: DNSSECScannerResult, resolver: dns.resolver.Resolver,
    ) -> DNSSECScannerResult:
        log.info(f"-------------------------------------")
        log.info(f"Entering {zone.name} zone")

        request = dns.message.make_query(
            zone.name, dns.rdatatype.DNSKEY, want_dnssec=True, payload=16384
        )
        response = dns.query.udp(request, zone.ip)

        zone.DNSKEY = self._get_rr_by_type(response.answer, dns.rdatatype.DNSKEY)
        zone.DNSKEY_RRSIG = self._get_rr_by_type(response.answer, dns.rdatatype.RRSIG)

        request = dns.message.make_query(
            self.domain, dns.rdatatype.A, want_dnssec=True, payload=16384
        )
        response = dns.query.udp(request, zone.ip)

        if response.answer:
            A = self._get_rr_by_type(response.answer, dns.rdatatype.A)
            zone.RR = A
            zone.RR_RRSIG = self._get_rr_by_type(response.answer, dns.rdatatype.RRSIG)
            self.validate_zone(zone)
            result.rrset = A
            return result

        ns = self._get_rr_by_type(response.authority, dns.rdatatype.NS)
        next_zone_name = str(ns.name)
        zone.child_name = next_zone_name

        request = dns.message.make_query(
            next_zone_name, dns.rdatatype.DS, want_dnssec=True, payload=16384
        )
        response = dns.query.udp(request, zone.ip)

        zone.RR = self._get_rr_by_type(response.answer, dns.rdatatype.DS)
        zone.RR_RRSIG = self._get_rr_by_type(response.answer, dns.rdatatype.RRSIG)

        next_zone_ip = resolver.query(ns.items[0].to_text(), "A").rrset.items[0].address

        self.validate_zone(zone)

        next_zone = Zone(next_zone_name, next_zone_ip, zone)

        return self.scan_zone(next_zone, result, resolver)

    def validate_zone(self, zone: Zone):
        # initialize zone
        zone.compute()

        if isinstance(zone.DNSKEY, dns.rrset.RRset) and isinstance(
            zone.DNSKEY_RRSIG, dns.rrset.RRset
        ):
            ksks = self._get_dnskey(zone.DNSKEY, Key.KSK)

            if not ksks:
                log.info(f"{zone.name} zone: No KSKs found")

            # validate KSKs
            trusted_ksks = []
            for i, ksk in enumerate(ksks):

                if zone.parent:
                    # we are in a sub-zone
                    ds_ = dns.dnssec.make_ds(
                        dns.name.from_text(zone.name),
                        ksk,
                        self._algorithm_hash_function(ksk.algorithm),
                    )
                    for j, ds in enumerate(self._get_rrs_by_type(zone.parent.RR.items, dns.rdatatype.DS)):
                        if str(zone.parent.RR.name) == zone.name and ds == ds_:
                            log.info(f"{zone.name} zone: KSK {i} successfully validated with DS {j}")
                            trusted_ksks.append(ksk)
                        else:
                            log.info(f"{zone.name} zone: Could not validate KSK {i} with DS {j}")
                else:
                    # we are in the root zone
                    ksk_ds = dns.dnssec.make_ds(".", ksk, "SHA256")
                    ksk_digest = ksk_ds.digest.hex().upper()

                    # TODO make full check with https://data.iana.org/root-anchors/root-anchors.xml
                    if (
                        ksk_digest
                        == "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"
                    ):
                        log.info(f"{zone.name} zone: Found trusted root KSK {i}")
                        trusted_ksks.append(ksk)
                    else:
                        log.info(f"{zone.name} zone: Untrusted root KSK {i}")

            # Validate DNSKEY RR with one of the RRSIGs
            for i, rr_sig in enumerate(zone.DNSKEY_RRSIG):
                try:
                    dns.dnssec.validate_rrsig(
                        zone.DNSKEY,
                        rr_sig,
                        {dns.name.from_text(zone.name): trusted_ksks},
                    )
                except dns.dnssec.ValidationFailure as e:
                    log.info(f"{zone.name} zone: Could not validate DNSKEY with RRSIG {i} ({e})")
                else:
                    log.info(f"{zone.name} zones: DNSKEY successfully validated with RRSIG {i}")
        else:
            if not isinstance(zone.DNSKEY, dns.rrset.RRset):
                log.info(f"{zone.name} zone: No DNSKEY found")
            if not isinstance(zone.DNSKEY_RRSIG, dns.rrset.RRset):
                log.info(f"{zone.name} zone: No DNSKEY RRSIG found")

        if (
            isinstance(zone.DNSKEY, dns.rrset.RRset)
            and isinstance(zone.RR, dns.rrset.RRset)
            and isinstance(zone.RR_RRSIG, dns.rrset.RRset)
        ):
            # Validate RRsets
            zsks = self._get_dnskey(zone.DNSKEY, Key.ZSK)
            for i, rr_sig in enumerate(zone.RR_RRSIG):
                try:
                    dns.dnssec.validate_rrsig(
                        zone.RR,
                        rr_sig,
                        {dns.name.from_text(zone.name): zsks},
                    )
                except dns.dnssec.ValidationFailure as e:
                    log.info(
                        f"{zone.name} zone: Could not validate {zone.RR_type} for {zone.child_name} with RRSIG {i} ({e})"
                    )
                else:
                    log.info(
                        f"{zone.name} zone: {zone.child_name} {zone.RR_type} record successfully validated with RRSIG {i}"
                    )
        else:
            if not isinstance(zone.RR, dns.rrset.RRset):
                log.info(
                    f"{zone.name} zone: No {zone.RR_type} RR found for {zone.child_name}"
                )
            if not isinstance(zone.RR_RRSIG, dns.rrset.RRset):
                log.info(f"{zone.name} zone: No RRSIG for {zone.RR_type} record found")

    @staticmethod
    def _get_rr_by_type(
        items: List[dns.rrset.RRset], rdtype: dns.rdatatype
    ) -> Optional[dns.rrset.RRset]:
        for item in items:
            if item.rdtype == rdtype:
                return item
        return rdtype

    @staticmethod
    def _get_rrs_by_type(
        items: List[dns.rrset.RRset], rdtype: dns.rdatatype
    ) -> List[dns.rrset.RRset]:
        result = []
        for item in items:
            if item.rdtype == rdtype:
                result.append(item)
        return result

    @staticmethod
    def _get_dnskey(keys: dns.rrset.RRset, k: Key) -> List[dns.rdtypes.ANY.DNSKEY]:
        result = []
        for key in keys:
            if key.flags == k.value:
                result.append(key)
        return result

    @staticmethod
    def _get_rrsig(rrsigs: dns.rrset.RRset, key):
        for rrsig in rrsigs:
            if rrsig.key_tag == dns.dnssec.key_id(key):
                return rrsig
        return None

    @staticmethod
    def _algorithm_hash_function(algo: Optional[int, str]) -> str:
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


if __name__ == "__main__":
    scanner = DNSSECScanner("yes.com")
    res = scanner.run_scan()
