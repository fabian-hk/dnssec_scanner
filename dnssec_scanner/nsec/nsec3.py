from __future__ import annotations
from typing import Optional, List, Tuple

import dns

from dnssec_scanner.validation import validate_rrset
from dnssec_scanner import utils
from dnssec_scanner.utils import DNSSECScannerResult, Zone

from dnssec_scanner.nsec import nsec_utils


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

    # TODO if there is only one NSEC3 record check if the owner hash is the hash of the QNAME

    # search for closest enclosure
    status, closest_encloser, next_closer_name = find_closest_encloser(
        nsec3s, nsec3param.items[0], qname
    )
    if status:
        msg = f"{zone.name} zone: Found closest encloser {closest_encloser}"
        result.append_log(msg)
    else:
        msg = f"{zone.name} zone: Could not find closest encloser for {qname.to_text()}"
        result.append_errors(msg)
    success &= status

    # check if the next closer name is covered by an NSEC3 record
    status = check_next_closer_name(nsec3s, nsec3param.items[0], next_closer_name)
    if status:
        msg = f"{zone.name} zone: Found NSEC3 that covers the next closer name"
        result.append_log(msg)
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
        next_name_hash = nsec_utils.nsec3_next_to_string(nsec3.items[0])
        if current_name_hash < next_closer_name_hash < next_name_hash:
            return True

    return False