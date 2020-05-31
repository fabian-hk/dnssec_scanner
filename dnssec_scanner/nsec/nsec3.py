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
    zone.RR = utils.remove_duplicates(response.answer)
    success &= validate_rrset(zone, result)
    nsec3param = utils.get_rr_by_type(zone.RR, dns.rdatatype.NSEC3PARAM)

    if check_ds:
        status = check_nsec_bitmap(nsec3s, nsec3param.items[0], zone.child_name)
        # If we want to show that there is no DS record for the QNAME
        # and we have found an NSEC3 record for the QNAME without the
        # DS record in its bitmap field we are already done.
        if status:
            return status

    # search for closest enclosure
    status, closest_encloser, next_closer_name = find_closest_encloser(
        nsec3s, nsec3param.items[0], qname
    )
    if status:
        msg = f"{zone.name} zone: Found closest encloser {closest_encloser}"
        result.logs.append(msg)
    else:
        msg = f"{zone.name} zone: Could not find closest encloser for {qname.to_text()}"
        result.errors.append(msg)
    success &= status

    # check if the next closer name is covered by an NSEC3 record
    status = check_name_cover(nsec3s, nsec3param.items[0], next_closer_name)
    if status:
        msg = f"{zone.name} zone: Found NSEC3 that covers the next closer name {next_closer_name}"
        result.logs.append(msg)
    else:
        msg = f"{zone.name} zone: Could not find a NSEC3 record that covers the next closer name {next_closer_name}"
        result.errors.append(msg)
    success &= status

    if check_ds:
        # If we want to show an insecure delegation at this point,
        # every NSEC3 record must have the Opt-Out flag set.
        success &= check_opt_out(nsec3s)
    else:
        # Proof "Three to Tango" to show that the domain name does not exist.
        # The only missing part is to show that no wildcard expansion could be used.
        # Source: https://tools.ietf.org/html/rfc7129#section-5.6
        success = check_name_cover(nsec3s, nsec3param.items[0], f"*.{closest_encloser}")
        if success:
            msg = f"{zone.name} zone: Found NSEC3 that covers the wildcard *.{closest_encloser}"
            result.logs.append(msg)
        else:
            msg = f"{zone.name} zone: Could not find a NSEC3 record that covers the  wildcard *.{closest_encloser}"
            result.errors.append(msg)

    return success


def find_closest_encloser(
        nsec3s: List[dns.rdtypes.ANY.NSEC3],
        nsec3param: dns.rdtypes.ANY.NSEC3PARAM,
        qname: dns.name.Name,
) -> Tuple[bool, str, str]:
    """
    This method tries to finds the closest encloser by chopping of
    labels of the QNAME until there is a NSEC3 for the hash value.

    :param nsec3s:
    :param nsec3param:
    :param qname:
    :return:
    """
    l = len(qname) - 1

    tmp = [t.decode() for t in qname]
    closest_encloser = ".".join(tmp)
    next_closer_name = closest_encloser

    for i in range(l):
        closest_enclosure_hash = nsec_utils.nsec3_hash(
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


def check_name_cover(
        nsec3s: List[dns.rdtypes.ANY.NSEC3],
        nsec3param: dns.rdtypes.ANY.NSEC3PARAM,
        name: str,
) -> bool:
    """
    This method checks if a name is covered by a NSEC3 record by hashing it
    and comparing it to all NSEC3s in the nsec3s list.

    :param nsec3s:
    :param nsec3param:
    :param next_closer_name:
    :return:
    """
    name_hash = nsec_utils.nsec3_hash(
        name, nsec3param.salt, nsec3param.iterations, nsec3param.algorithm,
    )

    for name, nsec3 in nsec3s:
        current_name_hash = name[0].decode("utf-8").upper()
        next_name_hash = nsec_utils.nsec3_next_to_string(nsec3.items[0])
        if current_name_hash < name_hash < next_name_hash:
            return True

    return False


def check_opt_out(nsec3s: List[dns.rdtypes.ANY.NSEC3]) -> bool:
    """
    Checks whether every NSEC3 record has
    the Opt-Out flag set.
    :param nsec3s:
    :return:
    """
    success = True

    for name, nsec3 in nsec3s:
        flags = nsec3.items[0].flags
        # Opt-Out flag is the least significant bit.
        # Source: https://tools.ietf.org/html/rfc5155#section-3.2
        success &= (flags & 0x01) == 1

    return success


def check_nsec_bitmap(
        nsec3s: List[dns.rdtypes.ANY.NSEC3],
        nsec3param: dns.rdtypes.ANY.NSEC3PARAM,
        name: str,
) -> bool:
    """
    Checks whether there is an NSEC3 record for the QNAME
    that does not have the type DS in its bitmap field.
    :param nsec3s:
    :param nsec3param:
    :param name:
    :return:
    """
    success = True

    # check whether the owner name matches to QNAME
    name_hash = nsec_utils.nsec3_hash(
        name, nsec3param.salt, nsec3param.iterations, nsec3param.algorithm,
    )
    owner_name, nsec3 = nsec3s[0]
    owner_hash = str(owner_name).split(".")[0]
    success &= name_hash == owner_hash

    # check if the bitmap field does not contain the DS type
    bitmap_list = nsec_utils.nsec_window_to_array(nsec3.items[0])
    success &= dns.rdatatype.DS not in bitmap_list

    return success
