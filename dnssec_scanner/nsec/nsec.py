from __future__ import annotations
from typing import Optional, List

import dns

from dnssec_scanner.utils import DNSSECScannerResult, Zone
from dnssec_scanner.nsec import nsec_utils


def nsec_proof_of_none_existence(
        nsecs: List[dns.rdtypes.ANY.NSEC],
        zone: Zone,
        result: DNSSECScannerResult,
        check_ds: Optional[bool] = False,
) -> bool:
    qname = dns.name.from_text(result.domain)

    if check_ds:
        success = False
        # Prove that no DS record exists
        # Source: https://tools.ietf.org/html/rfc7129#section-3.2
        for name, nsec in nsecs:
            if nsec_utils.compare_canonical_order(name, qname) == 0:
                if dns.rdatatype.DS not in nsec_utils.nsec_window_to_array(
                        nsec.items[0]
                ):
                    msg = f"{zone.name} zone: Prove successful that the DS record does not exist"
                    result.logs.append(msg)
                    success = True
                else:
                    msg = f"{zone.name} zone: DS record does exist"
                    result.errors.append(msg)

        if not success:
            msg = f"{zone.name} zone: Could not find a NSEC record for the QNAME"
            result.errors.append(msg)

        return success

    success = True

    # determine a possible closest encloser
    closest_encloser = find_closest_encloser(nsecs, qname)
    msg = f"{zone.name} zone: Found closest encloser {b'.'.join(closest_encloser).decode('utf-8')}"
    result.logs.append(msg)

    qname_list = list(qname)
    qname_list.reverse()

    # check that every closer name including the qname does not exist
    closer_names = closest_encloser.copy()
    for i in range(len(closest_encloser), len(qname_list)):
        closer_names.insert(0, qname_list[i])
        closest_encloser_name = dns.name.from_text(b".".join(closer_names))
        suc = nsec_utils.qname_covered_by_nsec(nsecs, closest_encloser_name)
        if suc:
            msg = f"{zone.name} zone: Proved that {closest_encloser_name.to_text()} does not exist"
            result.logs.append(msg)
        else:
            msg = f"{zone.name} zone: Could not proof that {closest_encloser_name.to_text()} does not exist"
            result.errors.append(msg)
        success &= suc

    # show that no wildcard expansion is possible
    closest_encloser.insert(0, b"*")
    wildcard = dns.name.from_text(b".".join(closest_encloser))
    suc = nsec_utils.qname_covered_by_nsec(nsecs, wildcard)
    if suc:
        msg = f"{zone.name} zone: Proved that the wildcard {wildcard.to_text()} does not exist"
        result.logs.append(msg)
    else:
        msg = f"{zone.name} zone: Wildcard {wildcard.to_text()} exists"
        result.errors.append(msg)
    success &= suc

    return success


def find_closest_encloser(
        nsecs: List[dns.rdtypes.ANY.NSEC], qname: dns.name.Name
) -> List[bytes]:
    closest_enclosers = []
    for nsec in nsecs:
        closest_enclosers.append(label_match(nsec, qname))

    m = 0
    result = None
    for closest_encloser in closest_enclosers:
        if len(closest_encloser) > m:
            result = closest_encloser
            m = len(closest_encloser)

    result.reverse()
    return result


def label_match(nsec: dns.rdtypes.ANY.NSEC, qname: dns.name.Name) -> List[bytes]:
    closest_encloser = []

    name, _ = nsec
    name_list = list(name)
    name_list.reverse()
    qname_list = list(qname)
    qname_list.reverse()

    for t in zip(qname_list, name_list):
        if t[0] == t[1]:
            closest_encloser.append(t[0])
        else:
            break

    return closest_encloser
