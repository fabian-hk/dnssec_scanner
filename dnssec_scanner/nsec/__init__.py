from __future__ import annotations
from typing import Optional

import dns

from dnssec_scanner.validation import validate_rrset
from dnssec_scanner import utils
from dnssec_scanner.utils import DNSSECScannerResult, Zone, State
from dnssec_scanner.nsec import nsec
from dnssec_scanner.nsec import nsec3


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
        validated &= nsec.nsec_proof_of_none_existence(nsecs, zone, result, check_ds)

    nsec3s = utils.get_rrs_by_type(zone.RR, dns.rdatatype.NSEC3)
    if nsec3s:
        validated &= nsec3.nsec3_proof_of_none_existence(nsec3s, zone, result, check_ds)

    if result.state == State.SECURE and check_ds and validated:
        result.state = State.INSECURE
    elif result.state == State.SECURE and not validated:
        result.state = State.BOGUS

    if validated and check_ds:
        msg = f"{zone.name} zone: Successfully proved that {zone.child_name} does not support DNSSEC"
        result.logs.append(msg)
    elif not validated and check_ds:
        msg = f"{zone.name} zone: Could not proof that {zone.child_name} does not support DNSSEC"
        result.errors.append(msg)

    return validated
