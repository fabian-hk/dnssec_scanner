from __future__ import annotations
from typing import List, Tuple
import logging

import dns

from . import utils
from .utils import DNSSECScannerResult, Zone, Key


logging.basicConfig(level=logging.INFO)
log = logging.getLogger("dnssec_scanner")


def validate_zone(zone: Zone, result: DNSSECScannerResult):
    if zone.DNSKEY and zone.DNSKEY_RRSIG:
        trusted_ksks, untrusted_ksks = validate_ksks(zone, result)
        validate_zsks(zone, trusted_ksks, untrusted_ksks, result)
    else:
        if not zone.DNSKEY:
            msg = f"{zone.name} zone: No DNSKEY found"
            log.info(msg)
            result.add_message(False, msg)
        if not zone.DNSKEY_RRSIG:
            msg = f"{zone.name} zone: No DNSKEY RRSIG found"
            log.info(msg)
            result.add_message(False, msg)
        result.compute_messages(False)


def validate_ksks(
    zone: Zone, result: DNSSECScannerResult
) -> Tuple[List[dns.rdtypes.ANY.DNSKEY], List[dns.rdtypes.ANY.DNSKEY]]:
    ksks = utils.get_dnskey(zone.DNSKEY, Key.KSK)

    if not ksks:
        msg = f"{zone.name} zone: No KSKs found"
        log.info(msg)
        result.add_message(False, msg)
        result.compute_messages(False)

    # validate KSKs
    trusted_ksks = []
    untrusted_ksks = []
    for ksk in ksks:
        if zone.parent:
            # we are in a sub-zone
            ds_ = dns.dnssec.make_ds(
                dns.name.from_text(zone.name),
                ksk,
                utils.algorithm_hash_function(ksk.algorithm),
            )
            trusted = False
            for rr_ds in utils.get_rrs_by_type(zone.parent.RR, dns.rdatatype.DS):
                for ds in rr_ds:
                    if str(rr_ds.name) == zone.name and ds == ds_:
                        msg = f"{zone.name} zone: KSK {ds_.key_tag} successfully validated"
                        log.info(msg)
                        result.add_message(True, msg)
                        trusted = True
            if trusted:
                trusted_ksks.append(ksk)
            else:
                msg = f"{zone.name} zone: Could not validate KSK {ds_.key_tag}"
                log.info(msg)
                result.add_message(False, msg)
                untrusted_ksks.append(ksk)
        else:
            # we are in the root zone
            ds_ = dns.dnssec.make_ds(".", ksk, "SHA256")
            ksk_digest = ds_.digest.hex().upper()

            # TODO make full check with https://data.iana.org/root-anchors/root-anchors.xml
            if (
                ksk_digest
                == "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"
            ):
                msg = f"{zone.name} zone: Found trusted root KSK {ds_.key_tag}"
                log.info(msg)
                result.add_message(True, msg)
                trusted_ksks.append(ksk)
            else:
                msg = f"{zone.name} zone: Untrusted root KSK {ds_.key_tag}"
                log.info(msg)
                result.add_message(False, msg)
                untrusted_ksks.append(ksk)
    result.compute_messages(False)

    if not trusted_ksks:
        msg = f"{zone.name} zone: Could not validate any KSK"
        log.info(msg)
        result.errors.append(msg)

    return trusted_ksks, untrusted_ksks


def validate_zsks(
    zone: Zone,
    trusted_ksks: List[dns.rdtypes.ANY.DNSKEY],
    untrusted_ksks: List[dns.rdtypes.ANY.DNSKEY],
    result: DNSSECScannerResult,
):
    # use trusted KSKs
    for ksk in trusted_ksks:
        key_id = dns.dnssec.key_id(ksk)
        sig = utils.get_rrsig(zone.DNSKEY_RRSIG, ksk)
        if sig:
            try:
                dns.dnssec.validate_rrsig(
                    zone.DNSKEY, sig, {dns.name.from_text(zone.name): [ksk]},
                )
            except dns.dnssec.ValidationFailure as e:
                msg = f"{zone.name} zones: Could not validate DNSKEY with trusted KSK {key_id} ({e})"
                log.info(msg)
                result.add_message(False, msg)
            else:
                msg = f"{zone.name} zones: DNSKEY successfully validated with trusted KSK {key_id}"
                log.info(msg)
                result.add_message(True, msg)
        else:
            msg = f"{zone.name} zones: No RRSIG for KSK {key_id}"
            log.info(msg)
            result.add_message(False, msg)
    suc = result.compute_messages(True)
    if not suc:
        msg = f"{zone.name} zones: Could not validated DNSKEY with a trusted KSK"
        log.info(msg)
        result.errors.append(msg)

    # use untrusted KSKs
    for ksk in untrusted_ksks:
        key_id = dns.dnssec.key_id(ksk)
        sig = utils.get_rrsig(zone.DNSKEY_RRSIG, ksk)
        if sig:
            try:
                dns.dnssec.validate_rrsig(
                    zone.DNSKEY, sig, {dns.name.from_text(zone.name): [ksk]},
                )
            except dns.dnssec.ValidationFailure as e:
                if suc:
                    msg = f"{zone.name} zone: Could not validate DNSKEY with trusted KSK {key_id} ({e})"
                else:
                    msg = f"{zone.name} zone: Could not validate DNSKEY with untrusted KSK {key_id} ({e})"
                log.info(msg)
                result.warnings.append(msg)
            else:
                if suc:
                    msg = f"{zone.name} zone: DNSKEY successfully validated with trusted KSK {key_id}"
                    log.info(msg)
                    result.info.append(msg)
                else:
                    msg = f"{zone.name} zone: DNSKEY successfully validated with untrusted KSK {key_id}"
                    log.info(msg)
                    result.warnings.append(msg)
        else:
            msg = f"{zone.name} zones: No RRSIG for KSK {key_id}"
            log.info(msg)
            result.errors.append(msg)

    # use ZSKs
    zsks = utils.get_dnskey(zone.DNSKEY, Key.ZSK)
    for zsk in zsks:
        key_id = dns.dnssec.key_id(zsk)
        sig = utils.get_rrsig(zone.DNSKEY_RRSIG, zsk)
        if sig:
            try:
                dns.dnssec.validate_rrsig(
                    zone.DNSKEY, sig, {dns.name.from_text(zone.name): [zsk]},
                )
            except dns.dnssec.ValidationFailure as e:
                msg = f"{zone.name} zone: Could not validate DNSKEY with ZSK {key_id} ({e})"
                log.info(msg)
                result.warnings.append(msg)
            else:
                msg = (
                    f"{zone.name} zone: DNSKEY successfully validated with ZSK {key_id}"
                )
                log.info(msg)
                result.info.append(msg)

    # check if there are RRSIGS that cannot be used with any key
    for rr_sig in zone.DNSKEY_RRSIG:
        suc = False
        for key in zone.DNSKEY:
            key_id = dns.dnssec.key_id(key)
            if rr_sig.key_tag == key_id:
                suc = True

        if not suc:
            msg = f"{zone.name} zone: RRSIG {rr_sig.key_tag} has no matching key"
            log.info(msg)
            result.warnings.append(msg)


def validate_rrset(zone: Zone, result: DNSSECScannerResult):
    type_dict = dns.rdatatype._by_value
    type_dict[65534] = "TYPE65534"

    # Validate RRsets
    zsks = utils.get_dnskey(zone.DNSKEY, Key.ZSK)
    for rr in zone.RR:
        if rr.rdtype != dns.rdatatype.RRSIG and rr.rdtype != dns.rdatatype.DNSKEY:
            rr_txt = type_dict[rr.rdtype]
            sigs = utils.get_rrsig_for_rr(zone.RR, rr.rdtype)
            if sigs:
                for sig in sigs:
                    try:
                        dns.dnssec.validate_rrsig(
                            rr, sig, {dns.name.from_text(zone.name): zsks},
                        )
                    except dns.dnssec.ValidationFailure as e:
                        msg = f"{zone.name} zone: Could not validate {rr_txt} for {zone.child_name} with ZSK {sig.key_tag} ({e})"
                        log.info(msg)
                        result.add_message(False, msg)
                    else:
                        msg = f"{zone.name} zone: {zone.child_name} {rr_txt}  record successfully validated with ZSK {sig.key_tag}"
                        log.info(msg)
                        result.add_message(True, msg)
                result.compute_messages(True)
            else:
                msg = f"{zone.name} zone: Could not find RRSIG for {rr_txt}"
                log.info(msg)
                result.add_message(False, msg)
                result.compute_messages(False)
