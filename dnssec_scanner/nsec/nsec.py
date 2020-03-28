from __future__ import annotations
from typing import Optional, List

import dns

from dnssec_scanner import utils
from dnssec_scanner.utils import DNSSECScannerResult, Zone
from dnssec_scanner.nsec import nsec_utils


def nsec_proof_of_none_existence(
        nsecs: List[dns.rdtypes.ANY.NSEC],
        zone: Zone,
        result: DNSSECScannerResult,
        check_ds: Optional[bool] = False,
) -> bool:
    success = True

    qname = dns.name.from_text(result.domain)

    if len(nsecs) == 1 and check_ds:
        # Prove that no DS record exists
        # Source: https://tools.ietf.org/html/rfc7129#section-3.2
        name, nsec = nsecs[0]
        if nsec_utils.compare_canonical_order(name, qname) == 0:
            if dns.rdatatype.DS not in nsec_utils.nsec_window_to_array(nsec):
                msg = f"{zone.name} zone: Prove successful that the DS record does not exist"
                result.logs.append(msg)
            else:
                msg = f"{zone.name} zone: DS record does exist"
                result.errors.append(msg)
                success = False
        else:
            msg = f"{zone.name} zone: NSEC owner name and QNAME is not the same"
            result.errors.append(msg)
            success = False
    else:
        # Prove that the domain name does not exist
        # Source: https://tools.ietf.org/html/rfc7129#section-5.3
        validated = {"w": False, "rr": False}
        for name, nsec in nsecs:
            wildcard = dns.name.from_text(f"*.{name.to_text()[:-1]}")

            if (
                    nsec_utils.compare_canonical_order(name, qname) == -1
                    and nsec_utils.compare_canonical_order(qname, nsec.items[0].next) == -1
            ):
                # check that the QNAME is covered by an NSEC record
                msg = (
                    f"{zone.name} zone: Found NSEC that {result.domain} does not exist"
                )
                result.logs.append(msg)
                validated["rr"] = True
            elif (
                    qname.is_subdomain(name)
                    and nsec_utils.compare_canonical_order(name, wildcard) == -1
                    and nsec_utils.compare_canonical_order(wildcard, nsec.items[0].next)
                    == -1
            ):
                # check that there was no possible wildcard expansion
                msg = f"{zone.name} zone: Found NSEC that no wildcard expansion for {result.domain} is possible"
                result.logs.append(msg)
                validated["w"] = True
            else:
                msg = f"{zone.name} zone: Found useless NSEC for {result.domain}"
                result.warnings.append(msg)

        if not validated["rr"]:
            msg = f"{zone.name} zone: Could not find a NSEC that covers the name {result.domain}"
            result.errors.append(msg)
            success = False

        if not validated["w"]:
            msg = f"{zone.name} zone: Could not validate that there is no wildcard for the name {result.domain}"
            result.errors.append(msg)
            success = False

    return success
