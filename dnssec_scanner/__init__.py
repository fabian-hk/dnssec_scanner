from typing import List, Optional

import logging
import dns.name
import dns.query
import dns.dnssec
import dns.message
import dns.resolver
import dns.rdatatype

logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger("dnssec_scanner")


def _get_rr_by_type(
    items: List[dns.rrset.RRset], rdtype: dns.rdatatype
) -> Optional[dns.rrset.RRset]:
    for item in items:
        if item.rdtype == rdtype:
            return item
    return None


def _get_dnskey(keys: dns.rrset.RRset, flags: int):
    for key in keys:
        if key.flags == flags:
            return key
    return None


def _get_rrsig(rrsigs: dns.rrset.RRset, key):
    for rrsig in rrsigs:
        if rrsig.key_tag == dns.dnssec.key_id(key):
            return rrsig
    return None


domain = "yes.com"
_resolver = "8.8.8.8"


def dnssec_scanner(domain: str, resolver: str):
    request = dns.message.make_query(domain, dns.rdatatype.A, want_dnssec=True)
    response = dns.query.udp(request, resolver)

    if response.rcode() != 0:
        print("Error")

    answer = response.answer

    rrset = _get_rr_by_type(answer, dns.rdatatype.RRSIG)
    if rrset:
        signer_name = rrset.items[0].signer
    else:
        print("No RRSIG record found")
        return

    request = dns.message.make_query(
        signer_name, dns.rdatatype.DNSKEY, want_dnssec=True
    )
    response = dns.query.udp(request, resolver)

    if response.rcode() != 0:
        print("Error")

    dnskey_answer = response.answer

    dnskey = _get_rr_by_type(dnskey_answer, dns.rdatatype.DNSKEY)

    if len(answer) != 2:
        print("Wrong anser length")

    rrset = _get_rr_by_type(answer, dns.rdatatype.A)
    rrsig = _get_rr_by_type(answer, dns.rdatatype.RRSIG)

    print(f"RRset: {rrset.to_text()}")
    print(f"RRsig: {rrsig.to_text()}")
    print(f"DNSKEY: {dnskey.to_text()}")
    print()

    try:
        dns.dnssec.validate_rrsig(rrset, rrsig.items[0], {signer_name: dnskey})
    except dns.dnssec.ValidationFailure as e:
        print("Validation failed")
        print(e)
    else:
        print("Validation successful")


def validate_root_zone():
    resolver = "199.7.83.42"
    request = dns.message.make_query(".", dns.rdatatype.DNSKEY, want_dnssec=True)
    response = dns.query.udp(request, resolver)

    dnskey = _get_rr_by_type(response.answer, dns.rdatatype.DNSKEY)
    rrsig = _get_rr_by_type(response.answer, dns.rdatatype.RRSIG)

    ksk = _get_dnskey(dnskey, 256)
    zsk = _get_dnskey(dnskey, 257)

    zsk_ds = dns.dnssec.make_ds(".", zsk, "SHA256")
    zsk_digest = zsk_ds.digest.hex().upper()

    # TODO make full check with https://data.iana.org/root-anchors/root-anchors.xml
    if zsk_digest != "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D":
        print("Untrusted root key")
        return

    try:
        dns.dnssec.validate_rrsig(
            dnskey, rrsig.items[0], {dns.name.from_text("."): [zsk]}
        )
    except dns.dnssec.ValidationFailure as e:
        print("Validation failed")
        print(e)
    else:
        print("Validation successful")


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
        ksk = _get_dnskey(self.DNSKEY, 257)
        self.KSK_id = dns.dnssec.key_id(ksk)
        zsk = _get_dnskey(self.DNSKEY, 256)
        self.ZSK_id = dns.dnssec.key_id(zsk)

    def __str__(self):
        self.compute()
        return (
            f"Zone: {self.name}\nKSK_id: {self.KSK_id}\nZSK_id: {self.ZSK_id}\n"
            f"DNSKEY RRSIG: {self.DNSKEY_RRSIG.to_text()}\n"
            f"RR: {self.RR.to_text()}\nRR RRSIG: {self.RR_RRSIG.to_text()}"
        )


def validate_zone(zone: Zone):
    # Validate key
    try:
        dns.dnssec.validate_rrsig(
            zone.DNSKEY, zone.DNSKEY_RRSIG.items[0], {dns.name.from_text(zone.name): zone.DNSKEY}
        )
    except dns.dnssec.ValidationFailure as e:
        log.info(f"{zone.name} zone: Could not validate ZSK ({e})")
    else:
        log.info(f"{zone.name} zones: ZSK successfully validated")

    # Validate RRsets
    try:
        dns.dnssec.validate_rrsig(
            zone.RR, zone.RR_RRSIG.items[0], {dns.name.from_text(zone.name): zone.DNSKEY}
        )
    except dns.dnssec.ValidationFailure as e:
        log.info(f"{zone.name} zone: Could not validate RRsets ({e})")
    else:
        log.info(f"{zone.name} zone: RR successfully validated")


def scan_zone(
    zone_ip: str, zone_name: str, resolver: dns.resolver.Resolver
) -> dns.rrset.RRset:
    log.info(f" Entering {zone_name} zone")

    zone = Zone(zone_name)

    request = dns.message.make_query(zone_name, dns.rdatatype.DNSKEY, want_dnssec=True)
    response = dns.query.udp(request, zone_ip)

    zone.DNSKEY = _get_rr_by_type(response.answer, dns.rdatatype.DNSKEY)
    zone.DNSKEY_RRSIG = _get_rr_by_type(response.answer, dns.rdatatype.RRSIG)

    request = dns.message.make_query("yes.com", dns.rdatatype.A, want_dnssec=True)
    response = dns.query.udp(request, zone_ip)

    if response.answer:
        A = _get_rr_by_type(response.answer, dns.rdatatype.A)
        zone.RR = A
        zone.RR_RRSIG = _get_rr_by_type(response.answer, dns.rdatatype.RRSIG)
        log.info(f"{zone}\n")
        validate_zone(zone)
        return A

    ns = _get_rr_by_type(response.authority, dns.rdatatype.NS)

    zone.RR = _get_rr_by_type(response.authority, dns.rdatatype.DS)
    zone.RR_RRSIG = _get_rr_by_type(response.authority, dns.rdatatype.RRSIG)

    next_zone_name = str(ns.name)

    ns_ip = resolver.query(ns.items[0].to_text(), "A").rrset.items[0].address

    log.info(f"{zone}")
    validate_zone(zone)

    return scan_zone(ns_ip, next_zone_name, resolver)


def resolve_ip() -> dns.rrset.RRset:
    root_zone = "199.7.83.42"
    resolver_ips = ["8.8.8.8", "8.8.4.4", "1.1.1.1"]

    resolver = dns.resolver.Resolver()
    resolver.nameservers = resolver_ips

    return scan_zone(root_zone, ".", resolver)


if __name__ == "__main__":
    # validate_root_zone()
    # dnssec_scanner(domain, _resolver)
    # validate_zone()
    print(resolve_ip().to_text())
