from typing import List, Set
import logging

import dns
import dns.resolver

from dnssec_scanner.dnssec_validation import (
    validate_zone,
    validate_rrset,
    proof_none_existence,
)
from dnssec_scanner.utils import DNSSECScannerResult, Zone
from dnssec_scanner import utils


logging.basicConfig(level=logging.INFO)
log = logging.getLogger("dnssec_scanner")


class DNSSECScanner:

    ROOT_ZONE = ("199.7.83.42", "l.root-servers.net.")
    RESOLVER_IPS = ["8.8.8.8", "8.8.4.4", "1.1.1.1"]

    def __init__(self, domain: str):
        self.domain = domain

    def run_scan(self) -> DNSSECScannerResult:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = self.RESOLVER_IPS

        zone = Zone(".", self.ROOT_ZONE[0], self.ROOT_ZONE[1], None)
        result = DNSSECScannerResult(self.domain)

        result = self.scan_zone(zone, result, resolver)

        return result

    def scan_zone(
        self, zone: Zone, result: DNSSECScannerResult, resolver: dns.resolver.Resolver,
    ) -> DNSSECScannerResult:
        log.info(f"-------------------------------------")
        log.info(f"Entering {zone.name} zone")

        response = utils.dns_query(zone.name, zone.ip, dns.rdatatype.DNSKEY)

        zone.DNSKEY = utils.get_rr_by_type(response.answer, dns.rdatatype.DNSKEY)
        zone.DNSKEY_RRSIG = utils.get_rr_by_type(response.answer, dns.rdatatype.RRSIG)

        response = utils.dns_query(self.domain, zone.ip, dns.rdatatype.SOA)

        rrsets = response.answer + response.authority
        if utils.get_rrs_by_type(rrsets, dns.rdatatype.SOA) or utils.get_rrs_by_type(
                rrsets, dns.rdatatype.CNAME
        ):
            validate_zone(zone, result)

            rr_types = self.find_records(zone)
            zone.RR = self.get_records(zone, rr_types)

            validate_rrset(zone, result)
            return result

        response = utils.dns_query(self.domain, zone.ip, dns.rdatatype.NS)

        ns = utils.get_rr_by_type(response.authority, dns.rdatatype.NS)
        next_zone_name = str(ns.name)
        zone.child_name = next_zone_name

        validate_zone(zone, result)

        response = utils.dns_query(next_zone_name, zone.ip, dns.rdatatype.DS)

        zone.RR = [
            utils.get_rr_by_type(response.answer, dns.rdatatype.DS),
            utils.get_rr_by_type(response.answer, dns.rdatatype.RRSIG),
        ]
        if not zone.RR[0]:
            zone.RR = response.authority
            proof_none_existence(zone, result)
            msg = f"{zone.name} zone: No DS RR found for {zone.child_name}"
            log.info(msg)
            result.add_message(False, msg)
            result.compute_messages(False)
        else:
            validate_rrset(zone, result)

        next_zone_domain = ns.items[0].to_text()
        next_zone_ip = resolver.query(next_zone_domain, "A").rrset.items[0].address

        next_zone = Zone(next_zone_name, next_zone_ip, next_zone_domain, zone)

        return self.scan_zone(next_zone, result, resolver)

    def find_records(self, zone: Zone) -> Set[int]:
        # define a default list of records in case ANY does not return anything
        rr_types = [
            dns.rdatatype.SOA,
            dns.rdatatype.NS,
            dns.rdatatype.A,
            dns.rdatatype.AAAA,
            dns.rdatatype.MX,
            dns.rdatatype.CNAME,
        ]

        # ask with ANY for all existing records
        request = dns.message.make_query(self.domain, dns.rdatatype.ANY, payload=16384)
        response = dns.query.tcp(request, zone.ip)

        for rr in response.answer:
            if rr.rdtype != dns.rdatatype.DNSKEY:
                rr_types.append(rr.rdtype)

        # remove duplicates
        rr_types = set(rr_types)
        return rr_types

    def get_records(self, zone: Zone, rrs: Set[int]) -> List[dns.rrset.RRset]:
        result = []
        for rr in rrs:
            response = utils.dns_query(self.domain, zone.ip, rr)
            # check if RR exists
            if utils.get_rrs_by_type(response.answer, rr):
                result.extend(response.answer)

        return result


if __name__ == "__main__":
    scanner = DNSSECScanner("google.com")
    res = scanner.run_scan()
    print(res)
