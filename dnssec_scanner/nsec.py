from __future__ import annotations

import logging
import dns
import hashlib
import base64

from dnssec_scanner.validation import validate_rrset
from dnssec_scanner import utils
from dnssec_scanner.utils import DNSSECScannerResult, Zone, State

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("dnssec_scanner")


def proof_none_existence(zone: Zone, result: DNSSECScannerResult):
    if result.state == State.INSECURE:
        # We do not have any keys in this zone.
        # So we do not have to try to proof that
        # no DNSSEC exists.
        return

    validated = validate_rrset(zone, result)
    for name, nsec3s in utils.get_rrs_by_type(zone.RR, dns.rdatatype.NSEC3):
        for nsec3 in nsec3s:
            domain_hash = nsec3_hash(
                zone.child_name, nsec3.salt, nsec3.iterations, nsec3.algorithm
            )
            current_domain_hash = name[0].decode("utf-8").upper()

            if domain_hash == current_domain_hash:
                rrsets_available = utils.nsec3_window_to_array(nsec3)
                if dns.rdatatype.DS not in rrsets_available:
                    check_dnssec_support(zone, result, validated)
            elif nsec3.flags & 0x01:  # the Opt-Out Flag is set
                next_domain_hash = utils.nsec3_next_to_string(nsec3)
                if current_domain_hash < domain_hash < next_domain_hash:
                    check_dnssec_support(zone, result, validated)
            else:
                msg = f"{zone.name} zone: Found NSEC3 RR sets but none matched to the current domain"
                result.add_message(False, msg)

    msg = f"{zone.name} zone: Could not proof that {zone.child_name} zone does not support DNSSEC"
    result.add_message(False, msg)
    result.compute_messages(False)


def check_dnssec_support(zone: Zone, result: DNSSECScannerResult, validated: bool):
    if validated:
        if result.state == State.SECURE:
            result.state = State.INSECURE
        msg = f"{zone.name} zone: {zone.child_name} does not support DNSSEC"
        log.info(msg)
        result.add_message(True, msg)


def nsec3_hash(domain: str, salt: str, iterations: int, algo: int) -> str:
    """
    Hash calculation: https://tools.ietf.org/html/rfc5155#section-5

    Domain encoding: https://tools.ietf.org/html/rfc4034#section-6.2
        Use method from dnspython

    Output encoding is base32hex: https://tools.ietf.org/html/rfc4648#section-7
        We need to substitute the characters.

    :param domain:
    :param salt:
    :param iterations:
    :return:
    """
    if algo != 1:
        raise ValueError("Wrong hash algorithm (only SHA1 is supported)")

    b32_to_b32hex = str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", "0123456789ABCDEFGHIJKLMNOPQRSTUV"
    )

    domain_encoded = dns.name.from_text(domain).canonicalize().to_wire()
    salt_encoded = salt
    if isinstance(salt, str):
        salt_encoded = bytes.fromhex(salt)

    digest = hashlib.sha1(domain_encoded + salt_encoded).digest()
    for i in range(iterations):
        digest = hashlib.sha1(digest + salt_encoded).digest()

    res = base64.b32encode(digest).decode("utf-8")
    res = res.translate(b32_to_b32hex)

    return res
