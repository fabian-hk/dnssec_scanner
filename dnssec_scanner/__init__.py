from typing import List, Set, Optional
import logging

import dns
import dns.resolver
import requests
from xml.etree import ElementTree
import dateutil
from dateutil.parser import parse
import datetime

from dnssec_scanner.validation import (
    validate_zone_keys,
    validate_rrset,
    validate_ds,
)
from dnssec_scanner import nsec
from dnssec_scanner.utils import DNSSECScannerResult, Zone, State, SoaState
from dnssec_scanner import utils
from dnssec_scanner.messages import Message, Msg
from dnssec_scanner.nsec import nsec_utils


logging.basicConfig(level=logging.INFO)
log = logging.getLogger("dnssec_scanner")


class DNSSECScanner:
    ROOT_ZONE = ("199.7.83.42", "l.root-servers.net.")
    RESOLVER_IPS = ["8.8.8.8", "8.8.4.4", "1.1.1.1"]

    def __init__(self, domain: str, type: Optional[int] = -1):
        """
        :param domain: Domain names as string
        :param type: One of the dns.rdatatype types
        """
        self.domain = domain
        self.requested_type = None
        if 0 <= type <= 65535:
            self.requested_type = type
        self.root_zone = self.initialize_root_zone()

    def run(self) -> DNSSECScannerResult:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = self.RESOLVER_IPS

        result = DNSSECScannerResult(self.domain, self.requested_type)

        result = self.scan_zone(self.root_zone, result, resolver)

        if self.requested_type:
            result.compute_requested_type(self.requested_type)

        return result

    def scan_zone(
            self, zone: Zone, result: DNSSECScannerResult, resolver: dns.resolver.Resolver,
    ) -> DNSSECScannerResult:
        log.info(f"Entering {zone.name} zone")

        self.get_dnskey(zone)

        validate_zone_keys(zone, result)

        status = self.search_soa(zone, result, resolver)

        if status == SoaState.FOUND:
            return result
        elif status == SoaState.FOUND_CNAME:
            return self.scan_zone(self.root_zone, result, resolver)

        next_zone = self.get_ns(zone, resolver)

        success = self.get_ds(zone, next_zone, result)

        if success:
            validate_ds(zone, result)

        return self.scan_zone(next_zone, result, resolver)

    def get_dnskey(self, zone: Zone):
        response = utils.dns_query(zone.name, zone.ip, dns.rdatatype.DNSKEY)

        zone.DNSKEY = utils.get_rr_by_type(response.answer, dns.rdatatype.DNSKEY)
        zone.DNSKEY_RRSIG = utils.get_rr_by_type(response.answer, dns.rdatatype.RRSIG)

    def search_soa(
            self, zone: Zone, result: DNSSECScannerResult, resolver: dns.resolver.Resolver
    ) -> SoaState:
        response = utils.dns_query(self.domain, zone.ip, dns.rdatatype.SOA)

        rrsets = response.answer + response.authority

        # RCODE 3 (NXDomain) means the domain name does not exist
        # Source: https://tools.ietf.org/html/rfc6895#section-2.3
        if response.rcode() == 3:
            # Domain name does not exist. Validate with NSEC the integrity of the none-existence.
            result.note = "Domain name does not exist"
            zone.RR = rrsets
            nsec.proof_none_existence(zone, result, False)
            return SoaState.FOUND
        elif utils.get_rrs_by_type(rrsets, dns.rdatatype.CNAME):
            # We have found a CNAME RR set so we have to start from the top again
            zone.RR = rrsets
            validate_rrset(zone, result)  # validate CNAME entry

            self.domain = str(
                utils.get_rr_by_type(rrsets, dns.rdatatype.CNAME).items[0].target
            )
            result.domain = self.domain
            return SoaState.FOUND_CNAME
        elif utils.get_rr_by_type(rrsets, dns.rdatatype.SOA):
            # We are in the zone for the domain name
            rr_types = self.find_records(zone)
            zone.RR = self.get_records(zone, rr_types)

            validate_rrset(zone, result, True)
            return SoaState.FOUND

        return SoaState.NOT_FOUND

    def get_ns(self, zone: Zone, resolver: dns.resolver.Resolver) -> Zone:
        response = utils.dns_query(self.domain, zone.ip, dns.rdatatype.NS)

        response = utils.get_rr_by_type(response.authority, dns.rdatatype.NS)
        next_zone_name = str(response.name)
        zone.child_name = next_zone_name

        next_zone_domain = response.items[0].to_text()
        next_zone_ip = resolver.query(next_zone_domain, "A").rrset.items[0].address

        return Zone(next_zone_name, next_zone_ip, next_zone_domain, zone)

    def get_ds(self, zone: Zone, next_zone: Zone, result: DNSSECScannerResult) -> bool:
        response = utils.dns_query(next_zone.name, zone.ip, dns.rdatatype.DS)

        zone.RR = response.answer
        if not utils.get_rr_by_type(zone.RR, dns.rdatatype.DS):
            zone.RR = response.authority
            nsec.proof_none_existence(zone, result, True)
            msg = Message(zone.name, zone.child_name, dns.rdatatype.DS)
            msg.set_not_found(Msg.NOT_FOUND)
            result.errors.append(str(msg))
            result.change_state(False)
            return False

        return True

    def find_records(self, zone: Zone) -> Set[int]:
        # define a default list of records in case ANY does not return anything
        rr_types = [
            dns.rdatatype.SOA,
            dns.rdatatype.NS,
            dns.rdatatype.A,
            dns.rdatatype.AAAA,
            dns.rdatatype.MX,
            dns.rdatatype.CNAME,
            dns.rdatatype.PTR,
            dns.rdatatype.WKS,
            dns.rdatatype.HINFO,
            dns.rdatatype.MINFO,
            dns.rdatatype.TXT,
        ]

        if self.requested_type:
            rr_types.append(self.requested_type)

        # ask with ANY for all existing records
        response = utils.dns_query(self.domain, zone.ip, dns.rdatatype.ANY)

        for rr in response.answer:
            if rr.rdtype != dns.rdatatype.DNSKEY and rr.rdtype != dns.rdatatype.RRSIG:
                rr_types.append(rr.rdtype)

        # Try to query a NSEC or NSEC3 record. This would tell
        # us all available record types.
        rr_types.extend(self.find_records_from_nsec(zone))

        # remove duplicates
        rr_types = set(rr_types)
        # remove NSEC and NSEC3 record types
        if dns.rdatatype.NSEC in rr_types:
            rr_types.remove(dns.rdatatype.NSEC)
        if dns.rdatatype.NSEC3 in rr_types:
            rr_types.remove(dns.rdatatype.NSEC3)
        return rr_types

    def find_records_from_nsec(self, zone: Zone) -> Set[int]:
        response = utils.dns_query(self.domain, zone.ip, dns.rdatatype.NSEC)
        rrsets = response.answer + response.authority

        nsec = utils.get_rr_by_type(rrsets, dns.rdatatype.NSEC)
        if nsec:
            return nsec_utils.nsec_window_to_array(nsec.items[0])

        nsec3 = utils.get_rr_by_type(rrsets, dns.rdatatype.NSEC3)
        if nsec3:
            return nsec_utils.nsec_window_to_array(nsec3.items[0])

        return set()

    def get_records(self, zone: Zone, rrs: Set[int]) -> List[dns.rrset.RRset]:
        output = []
        for rr in rrs:
            response = utils.dns_query(self.domain, zone.ip, rr)
            # check if RR exists
            rrsets = utils.get_rrs_by_type(response.answer, rr)
            if rrsets:
                output.extend(response.answer)

            for name, rrset in rrsets:
                # only for pretty printing
                for entry in rrset.to_text().split("\n"):
                    log.info(f"Found DNS entry: {entry}")

        return output

    def initialize_root_zone(self) -> Zone:
        zone = Zone("", "", "", None)
        r = requests.get("https://data.iana.org/root-anchors/root-anchors.xml")
        root = ElementTree.fromstring(r.content)
        for el in root.findall("KeyDigest"):
            now = datetime.datetime.now(dateutil.tz.tzutc())

            valid_from = dateutil.parser.parse(el.get("validFrom"))

            valid_until = datetime.datetime.now(dateutil.tz.tzutc())
            if el.get("validUntil"):
                valid_until = parse(el.get("validUntil"))

            rrset = dns.rrset.from_text(
                ".",
                "-1",
                dns.rdataclass.IN,
                dns.rdatatype.DS,
                f"{el.find('KeyTag').text} {el.find('Algorithm').text} {el.find('DigestType').text} {el.find('Digest').text.lower()}",
            )

            if valid_from < now <= valid_until:
                zone.trusted_DS.append(rrset)
            else:
                zone.untrusted_DS.append(rrset)

        root_zone = Zone(".", self.ROOT_ZONE[0], self.ROOT_ZONE[1], zone)
        return root_zone
