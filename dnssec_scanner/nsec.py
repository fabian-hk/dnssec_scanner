from __future__ import annotations
from typing import Optional, List, Tuple

import logging
import dns
import hashlib
import base64

from dnssec_scanner.validation import validate_rrset
from dnssec_scanner import utils
from dnssec_scanner.utils import DNSSECScannerResult, Zone, State

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("dnssec_scanner")


def proof_none_existence(
        zone: Zone, result: DNSSECScannerResult, check_ds: Optional[bool] = False
) -> bool:
    if result.state == State.INSECURE:
        # We do not have any keys in this zone.
        # So we do not have to try to proof that
        # no DNSSEC exists.
        return True

    validated = validate_rrset(zone, result)

    nsecs = utils.get_rrs_by_type(zone.RR, dns.rdatatype.NSEC)
    if nsecs:
        validated &= nsec_proof_of_none_existence(nsecs, zone, result, check_ds)

    nsec3s = utils.get_rrs_by_type(zone.RR, dns.rdatatype.NSEC3)
    if nsec3s:
        validated &= nsec3_proof_of_none_existence(nsec3s, zone, result, check_ds)

    if result.state == State.SECURE and check_ds:
        result.state = State.INSECURE

    if validated and check_ds:
        msg = f"{zone.name} zone: Successfully proved that {zone.child_name} does not support DNSSEC"
        result.append_info(msg)
    elif not validated and check_ds:
        msg = f"{zone.name} zone: Could not proof that {zone.child_name} does not support DNSSEC"
        result.append_errors(msg)

    return validated


def nsec3_proof_of_none_existence(
        nsec3s: List[dns.rdtypes.ANY.NSEC3],
        zone: Zone,
        result: DNSSECScannerResult,
        check_ds: Optional[bool] = False,
) -> bool:
    """
    This method does the closest encloser proof after: https://tools.ietf.org/html/rfc7129#section-5.5
    :param nsec3s:
    :param zone:
    :param result:
    :param check_ds:
    :return:
    """
    success = True

    qname = dns.name.from_text(result.domain)

    # query NSEC3 paramter from zone and validate them
    response = utils.dns_query(zone.name, zone.ip, dns.rdatatype.NSEC3PARAM)
    zone.RR += response.answer
    success &= validate_rrset(zone, result)
    nsec3param = utils.get_rr_by_type(zone.RR, dns.rdatatype.NSEC3PARAM)

    # search for closest enclosure
    status, closest_encloser, next_closer_name = find_closest_encloser(
        nsec3s, nsec3param.items[0], qname
    )
    if status:
        msg = f"{zone.name} zone: Found closest encloser {closest_encloser}"
        result.append_info(msg)
    else:
        msg = f"{zone.name} zone: Could not find closest encloser for {qname.to_text()}"
        result.append_errors(msg)
    success &= status

    # check if the next closer name is covered by an NSEC3 record
    status = check_next_closer_name(nsec3s, nsec3param.items[0], next_closer_name)
    if status:
        msg = f"{zone.name} zone: Found NSEC3 that covers the next closer name"
        result.append_info(msg)
    else:
        msg = f"{zone.name} zone: Could not find a NSEC3 record that covers the next closer name"
        result.append_errors(msg)
    success &= status

    if not check_ds:
        # Proof "Three to Tango" to show that the domain name does not exist.
        # The only missing part is to show that no wildcard expansion could be used.
        # Source: https://tools.ietf.org/html/rfc7129#section-5.6
        # TODO Three to Tango
        pass

    return success


def find_closest_encloser(
        nsec3s: List[dns.rdtypes.ANY.NSEC3],
        nsec3param: dns.rdtypes.ANY.NSEC3PARAM,
        qname: dns.name.Name,
) -> Tuple[bool, str, str]:
    l = len(qname) - 1

    tmp = [t.decode() for t in qname]
    closest_encloser = ".".join(tmp)
    next_closer_name = closest_encloser

    for i in range(l):
        closest_enclosure_hash = dns.dnssec.nsec3_hash(
            closest_encloser,
            nsec3param.salt,
            nsec3param.iterations,
            nsec3param.algorithm,
        )

        for name, nsec3 in nsec3s:
            current_name_hash = name[0].decode("utf-8").upper()
            if closest_enclosure_hash == current_name_hash:
                return True, closest_encloser, next_closer_name

        next_closer_name = closest_encloser
        tmp = [t.decode() for t in qname[i + 1:]]
        closest_encloser = ".".join(tmp)

    return False, closest_encloser, next_closer_name


def check_next_closer_name(
        nsec3s: List[dns.rdtypes.ANY.NSEC3],
        nsec3param: dns.rdtypes.ANY.NSEC3PARAM,
        next_closer_name: str,
) -> bool:
    next_closer_name_hash = dns.dnssec.nsec3_hash(
        next_closer_name, nsec3param.salt, nsec3param.iterations, nsec3param.algorithm,
    )

    for name, nsec3 in nsec3s:
        current_name_hash = name[0].decode("utf-8").upper()
        next_name_hash = utils.nsec3_next_to_string(nsec3.items[0])
        if current_name_hash < next_closer_name_hash < next_name_hash:
            return True

    return False


def nsec_proof_of_none_existence(
        nsecs: List[dns.rdtypes.ANY.NSEC],
        zone: Zone,
        result: DNSSECScannerResult,
        check_ds: Optional[bool] = False,
) -> bool:
    success = False

    qname = dns.name.from_text(result.domain)

    if len(nsecs) == 1 and check_ds:
        # Prove that no DS record exists
        # Source: https://tools.ietf.org/html/rfc7129#section-3.2
        name, nsec = nsecs[0]
        if compare_canonical_order(name, qname) == 0:
            if dns.rdatatype.DS not in utils.nsec_window_to_array(nsec):
                msg = f"{zone.name} zone: Prove successful that the DS record does not exist"
                result.add_message(True, msg)
                success = True
            else:
                msg = f"{zone.name} zone: DS record does exist"
                result.add_message(False, msg)
        else:
            msg = f"{zone.name} zone: NSEC owner name and QNAME is not the same"
            result.add_message(False, msg)
    elif len(nsecs) == 2 and not check_ds:
        # Prove that the domain name does not exist
        # Source: https://tools.ietf.org/html/rfc7129#section-5.3
        count = 0
        for name, nsec in nsecs:
            wildcard = dns.name.from_text(f"*.{name.to_text()}")

            if (
                    compare_canonical_order(name, qname) == -1
                    and compare_canonical_order(qname, nsec.items[0].next) == -1
            ):
                # check that the QNAME is covered by an NSEC record
                msg = (
                    f"{zone.name} zone: Found NSEC that {result.domain} does not exist"
                )
                result.add_message(True, msg)
                count += 1
            elif (
                    qname.is_subdomain(name)
                    and compare_canonical_order(name, wildcard) == -1
                    and compare_canonical_order(wildcard, nsec.items[0].next) == -1
            ):
                # check that there was no possible wildcard expansion
                msg = f"{zone.name} zone: Found NSEC that no wildcard expansion for {result.domain} is possible"
                result.add_message(True, msg)
                count += 1
            else:
                msg = f"{zone.name} zone: Found useless NSEC for {result.domain}"
                result.add_message(False, msg)

        if count != 2:
            msg = f"{zone.name} zone: Failed to prove that the name {result.domain} does not exist"
            result.add_message(False, msg)
        else:
            success = True
    else:
        msg = (
            f"{zone.name} zone: Prove of none-existence failed for name {result.domain}"
        )
        result.add_message(False, msg)

    result.compute_messages(True)
    return success


def qname_covered_by_nsec(
        nsecs: List[dns.rdtypes.ANY.NSEC], qname: dns.name.Name
) -> bool:
    for name, nsec in nsecs:
        if (
                compare_canonical_order(name, qname) == -1
                and compare_canonical_order(qname, nsec.items[0].next) == -1
        ):
            return True

    return False


def compare_canonical_order(name1: Tuple[bytes], name2: Tuple[bytes]) -> int:
    """
    returns 0 if both are equal
    returns -1 if name1 < name2
    returns 1 if name1 > name2

    :param name1:
    :param name2:
    """
    lower = bytes.maketrans(
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZ", b"abcdefghijklmnopqrstuvwxyz"
    )

    l = min(len(name1), len(name2))
    d_n1 = len(name1) - l
    d_n2 = len(name2) - l

    for i in range(l - 1, -1, -1):
        n1 = bytes(name1[i + d_n1]).translate(lower)
        n2 = bytes(name2[i + d_n2]).translate(lower)
        if n1 < n2:
            return -1
        elif n1 > n2:
            return 1

    if len(name1) > len(name2):
        return 1
    elif len(name1) < len(name2):
        return -1

    return 0


def check_dnssec_support(zone: Zone, result: DNSSECScannerResult, validated: bool):
    if validated:
        if result.state == State.SECURE:
            result.state = State.INSECURE
        msg = f"{zone.name} zone: {zone.child_name} does not support DNSSEC"
        log.info(msg)
        result.add_message(True, msg)


def nsec3_hash(
        domain: str, salt: Optional[str, bytes], iterations: int, algo: int
) -> str:
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
        if len(salt) % 2 == 0:
            salt_encoded = bytes.fromhex(salt)
        else:
            raise ValueError("Invalid salt length")

    digest = hashlib.sha1(domain_encoded + salt_encoded).digest()
    for i in range(iterations):
        digest = hashlib.sha1(digest + salt_encoded).digest()

    output = base64.b32encode(digest).decode("utf-8")
    output = output.translate(b32_to_b32hex)

    return output
