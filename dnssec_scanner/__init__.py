from typing import List, Optional

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


class DNSSECScannerResult:
    def __init__(self, domain: str):
        self.domain = domain
        self.state = State.SECURE
        self.errors = []


class Zone:
    name: str
    DNSKEY: dns.rrset.RRset
    KSK_id: int
    ZSK_id: int
    DNSKEY_RRSIG: dns.rrset.RRset
    RR: dns.rrset.RRset
    RR_RRSIG: dns.rrset.RRset
    child = None

    def __init__(self, name: str):
        self.name = name

    def compute(self):
        if self.DNSKEY:
            ksk = DNSSECScanner._get_dnskey(self.DNSKEY, 257)
            self.KSK_id = dns.dnssec.key_id(ksk)
            zsk = DNSSECScanner._get_dnskey(self.DNSKEY, 256)
            self.ZSK_id = dns.dnssec.key_id(zsk)
        else:
            self.KSK_id = -1
            self.ZSK_id = -1

    def __str__(self):
        self.compute()
        return (
            f"Zone: {self.name}\nKSK_id: {self.KSK_id}\nZSK_id: {self.ZSK_id}\n"
            f"DNSKEY RRSIG: {self.DNSKEY_RRSIG.to_text()}\n"
            f"RR: {self.RR.to_text()}\nRR RRSIG: {self.RR_RRSIG.to_text()}"
        )


class DNSSECScanner:

    ROOT_ZONE = "199.7.83.42"
    RESOLVER_IPS = ["8.8.8.8", "8.8.4.4", "1.1.1.1"]

    def __init__(self, domain: str):
        self.domain = domain
        self.result = DNSSECScannerResult(self.domain)

    def run_scan(self) -> dns.rrset.RRset:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = self.RESOLVER_IPS

        return self.scan_zone(self.ROOT_ZONE, ".", resolver)

    def scan_zone(
        self, zone_ip: str, zone_name: str, resolver: dns.resolver.Resolver
    ) -> dns.rrset.RRset:
        log.info(f" Entering {zone_name} zone")

        zone = Zone(zone_name)

        request = dns.message.make_query(
            zone_name, dns.rdatatype.DNSKEY, want_dnssec=True
        )
        response = dns.query.udp(request, zone_ip)

        zone.DNSKEY = self._get_rr_by_type(response.answer, dns.rdatatype.DNSKEY)
        zone.DNSKEY_RRSIG = self._get_rr_by_type(response.answer, dns.rdatatype.RRSIG)

        request = dns.message.make_query(self.domain, dns.rdatatype.A, want_dnssec=True)
        response = dns.query.udp(request, zone_ip)

        if response.answer:
            A = self._get_rr_by_type(response.answer, dns.rdatatype.A)
            zone.RR = A
            zone.RR_RRSIG = self._get_rr_by_type(response.answer, dns.rdatatype.RRSIG)
            # log.debug(f"{zone}")
            self.validate_zone(zone)
            return A

        ns = self._get_rr_by_type(response.authority, dns.rdatatype.NS)
        next_zone_name = str(ns.name)

        request = dns.message.make_query(
            next_zone_name, dns.rdatatype.DS, want_dnssec=True
        )
        response = dns.query.udp(request, zone_ip)

        zone.RR = self._get_rr_by_type(response.answer, dns.rdatatype.DS)
        zone.RR_RRSIG = self._get_rr_by_type(response.answer, dns.rdatatype.RRSIG)

        ns_ip = resolver.query(ns.items[0].to_text(), "A").rrset.items[0].address

        # log.debug(f"{zone}")
        self.validate_zone(zone)

        return self.scan_zone(ns_ip, next_zone_name, resolver)

    def validate_zone(self, zone: Zone):
        # Validate KSK from the root zone
        if zone.name == ".":
            ksk = self._get_dnskey(zone.DNSKEY, 257)

            ksk_ds = dns.dnssec.make_ds(".", ksk, "SHA256")
            ksk_digest = ksk_ds.digest.hex().upper()

            # TODO make full check with https://data.iana.org/root-anchors/root-anchors.xml
            if (
                ksk_digest
                != "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"
            ):
                log.info(f"Untrusted root KSK")
            else:
                log.info(f"Found trusted root KSK")

        if isinstance(zone.DNSKEY, dns.rrset.RRset) and isinstance(
            zone.DNSKEY_RRSIG, dns.rrset.RRset
        ):
            # Validate ZSK
            try:
                dns.dnssec.validate_rrsig(
                    zone.DNSKEY,
                    zone.DNSKEY_RRSIG.items[0],
                    {dns.name.from_text(zone.name): zone.DNSKEY},
                )
            except dns.dnssec.ValidationFailure as e:
                log.info(f"{zone.name} zone: Could not validate ZSK ({e})")
            else:
                log.info(f"{zone.name} zones: ZSK successfully validated")
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
            try:
                dns.dnssec.validate_rrsig(
                    zone.RR,
                    zone.RR_RRSIG.items[0],
                    {dns.name.from_text(zone.name): zone.DNSKEY},
                )
            except dns.dnssec.ValidationFailure as e:
                log.info(f"{zone.name} zone: Could not validate {dns.rdatatype._by_value[zone.RR.rdtype]} ({e})")
            else:
                log.info(f"{zone.name} zone: {dns.rdatatype._by_value[zone.RR.rdtype]} record successfully validated")
        else:
            if not isinstance(zone.RR, dns.rrset.RRset):
                log.info(
                    f"{zone.name} zone: No {dns.rdatatype._by_value[zone.RR]} RR found"
                )
            if not isinstance(zone.RR_RRSIG, dns.rrset.RRset):
                rrset_type = dns.rdatatype._by_value[
                    zone.RR.rdtype if isinstance(zone.RR, dns.rrset.RRset) else zone.RR
                ]
                log.info(f"{zone.name} zone: No RRSIG for {rrset_type} record found")

    @staticmethod
    def _get_rr_by_type(
        items: List[dns.rrset.RRset], rdtype: dns.rdatatype
    ) -> Optional[dns.rrset.RRset]:
        for item in items:
            if item.rdtype == rdtype:
                return item
        return rdtype

    @staticmethod
    def _get_dnskey(keys: dns.rrset.RRset, flags: int):
        for key in keys:
            if key.flags == flags:
                return key
        return None

    @staticmethod
    def _get_rrsig(rrsigs: dns.rrset.RRset, key):
        for rrsig in rrsigs:
            if rrsig.key_tag == dns.dnssec.key_id(key):
                return rrsig
        return None


if __name__ == "__main__":
    scanner = DNSSECScanner("yes.com")
    rrset = scanner.run_scan()
    print(rrset.to_text())
