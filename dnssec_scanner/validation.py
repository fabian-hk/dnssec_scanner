from __future__ import annotations
from typing import List, Tuple, Optional
import logging

import dns

from . import utils
from .utils import DNSSECScannerResult, Zone, Key
from .messages import Message, Validator, Msg, Types

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("dnssec_scanner")


def validate_zone(zone: Zone, result: DNSSECScannerResult):
    if zone.DNSKEY and zone.DNSKEY_RRSIG:
        trusted_ksks, untrusted_ksks = validate_ksks(zone, result)
        validate_zsks(zone, trusted_ksks, untrusted_ksks, result)
    else:
        if not zone.DNSKEY:
            msg = Message(zone.name, "", dns.rdatatype.DNSKEY)
            msg.set_not_found(Msg.NOT_FOUND)
            result.errors.append(str(msg))
        if not zone.DNSKEY_RRSIG:
            msg = Message(zone.name, "", dns.rdatatype.DNSKEY)
            msg.set_not_found(Msg.RRSIG_NOT_FOUND)
            result.errors.append(str(msg))
        result.change_state(False)


def validate_ksks(
        zone: Zone, result: DNSSECScannerResult
) -> Tuple[List[dns.rdtypes.ANY.DNSKEY], List[dns.rdtypes.ANY.DNSKEY]]:
    """
    We consider the validation as successful if at least
    one KSK can be validated with a trusted DS record.
    :param zone:
    :param result:
    :return:
    """
    success = False

    ksks = utils.get_dnskey(zone.DNSKEY, Key.KSK)

    if not ksks:
        result.errors.append(f"{zone.name} zone: No KSKs found")
        result.change_state(False)

    # validate KSKs with trusted DS
    msgs = []  # type: List[Message]
    trusted_ksks = []
    untrusted_ksks = []
    for ksk in ksks:
        dss = utils.get_ds_by_dnskey(zone.parent.trusted_DS, ksk)

        msg = Message(zone.name, "", f"{Types.KSK} {dns.dnssec.key_id(ksk)}")
        if dss:
            for name, ds in dss:
                ds_ = dns.dnssec.make_ds(
                    dns.name.from_text(zone.name),
                    ksk,
                    utils.digest_algorithm(ds.digest_type),
                )
                if name == zone.name and ds == ds_:
                    msg.set_success(
                        Validator.DS, f"{ds.key_tag} {ds.algorithm} {ds.digest_type}",
                    )
                else:
                    msg.add_warning(
                        Validator.DS,
                        f"{ds.key_tag} {ds.algorithm} {ds.digest_type}",
                        Msg.VALIDATION_FAILURE,
                    )
        else:
            msg.set_not_found(Msg.DS_NOT_FOUND)

        if msg:
            trusted_ksks.append(ksk)
        else:
            untrusted_ksks.append(ksk)

            # try to validate the KSK with a untrusted DS RR set
            dss = utils.get_ds_by_dnskey(zone.parent.untrusted_DS, ksk)

            if dss:
                for name, ds in dss:
                    ds_ = dns.dnssec.make_ds(
                        dns.name.from_text(zone.name),
                        ksk,
                        utils.digest_algorithm(ds.digest_type),
                    )
                    if name == zone.name and ds == ds_:
                        msg.add_warning(
                            Validator.UNTRUSTED_DS,
                            f"{ds.key_tag} {ds.algorithm} {ds.digest_type}",
                            Msg.VALIDATED,
                        )
                    else:
                        msg.add_warning(
                            Validator.UNTRUSTED_DS,
                            f"{ds.key_tag} {ds.algorithm} {ds.digest_type}",
                            Msg.VALIDATION_FAILURE,
                        )
        msgs.append(msg)

    success = result.compute_batch(msgs)

    if not success:
        result.errors.append(f"{zone.name} zone: Could not validate any KSK")
        result.change_state(success)

    return trusted_ksks, untrusted_ksks


def validate_zsks(
    zone: Zone,
    trusted_ksks: List[dns.rdtypes.ANY.DNSKEY],
    untrusted_ksks: List[dns.rdtypes.ANY.DNSKEY],
    result: DNSSECScannerResult,
):
    # use trusted KSKs
    msgs = []  # type: List[Message]
    for ksk in trusted_ksks:
        msg = Message(zone.name, "", dns.rdatatype.DNSKEY)

        key_id = dns.dnssec.key_id(ksk)
        sig = utils.get_rrsig(zone.DNSKEY_RRSIG, ksk)
        if sig:
            try:
                dns.dnssec.validate_rrsig(
                    zone.DNSKEY, sig, {dns.name.from_text(zone.name): [ksk]},
                )
            except dns.dnssec.ValidationFailure as e:
                msg.add_warning(
                    Validator.KSK, key_id, f"{Msg.VALIDATION_FAILURE} ({e})"
                )
            else:
                msg.set_success(Validator.KSK, key_id)
        else:
            msg.set_not_found(Msg.RRSIG_NOT_FOUND)
        msgs.append(msg)

    success = result.compute_batch(msgs)

    if not success:
        msg = f"{zone.name} zones: Could not validate DNSKEY with a trusted KSK"
        result.errors.append(msg)
        result.change_state(success)
        validator = Validator.UNTRUSTED_KSK
    else:
        validator = Validator.KSK

    # use untrusted KSKs
    for ksk in untrusted_ksks:
        msg = Message(zone.name, "", dns.rdatatype.DNSKEY)
        key_id = dns.dnssec.key_id(ksk)
        sig = utils.get_rrsig(zone.DNSKEY_RRSIG, ksk)
        if sig:
            try:
                dns.dnssec.validate_rrsig(
                    zone.DNSKEY, sig, {dns.name.from_text(zone.name): [ksk]},
                )
            except dns.dnssec.ValidationFailure as e:
                msg.add_warning(validator, key_id, f"{Msg.VALIDATION_FAILURE} ({e})")
            else:
                msg.set_success(validator, key_id)
                msg.validated = success
        else:
            msg.set_not_found(Msg.RRSIG_NOT_FOUND)
        result.compute_message(msg)

    # use ZSKs
    zsks = utils.get_dnskey(zone.DNSKEY, Key.ZSK)
    for zsk in zsks:
        msg = Message(zone.name, "", dns.rdatatype.DNSKEY)
        key_id = dns.dnssec.key_id(zsk)
        sig = utils.get_rrsig(zone.DNSKEY_RRSIG, zsk)
        if sig:
            try:
                dns.dnssec.validate_rrsig(
                    zone.DNSKEY, sig, {dns.name.from_text(zone.name): [zsk]},
                )
            except dns.dnssec.ValidationFailure as e:
                msg.add_warning(
                    Validator.ZSK, key_id, f"{Msg.VALIDATION_FAILURE} ({e})"
                )
            else:
                msg.set_success(Validator.ZSK, key_id)
        result.compute_message(msg)

    # check if there are RRSIGS that cannot be used with any key
    for rr_sig in zone.DNSKEY_RRSIG:
        suc = False
        for key in zone.DNSKEY:
            key_id = dns.dnssec.key_id(key)
            if rr_sig.key_tag == key_id:
                suc = True

        if not suc:
            msg = f"{zone.name} zone: RRSIG {rr_sig.key_tag} has no matching key"
            result.warnings.append(msg)


def validate_ds(zone: Zone, result: DNSSECScannerResult) -> bool:
    success = (
        False  # if one DS record can be validated we define the check as successful
    )

    zsks = utils.get_dnskey(zone.DNSKEY, Key.ZSK)
    for rr in zone.RR:
        if rr.rdtype == dns.rdatatype.DS:
            msg = Message(zone.name, rr.name, rr.rdtype)
            sigs = utils.get_rrsig_for_rr(zone.RR, rr)
            if sigs:
                for sig in sigs:
                    try:
                        dns.dnssec.validate_rrsig(
                            rr, sig, {dns.name.from_text(zone.name): zsks},
                        )
                    except dns.dnssec.ValidationFailure as e:
                        msg.add_warning(
                            Validator.ZSK,
                            sig.key_tag,
                            f"{Msg.VALIDATION_FAILURE} ({e})",
                        )
                        zone.untrusted_DS.append(rr)
                    else:
                        msg.set_success(Validator.ZSK, sig.key_tag)
                        zone.trusted_DS.append(rr)
            else:
                msg.set_not_found(Msg.RRSIG_NOT_FOUND)
                zone.untrusted_DS.append(rr)

            success |= result.compute_message(msg)

    result.change_state(success)
    return success


def validate_rrset(
        zone: Zone, result: DNSSECScannerResult, save: Optional[bool] = False
) -> bool:
    res = True

    # initialize DNSSECScannerResult note variable
    if save:
        result.note = "Found RR sets:"

    # Validate RRsets
    zsks = utils.get_dnskey(zone.DNSKEY, Key.ZSK)
    for rr in zone.RR:
        if rr.rdtype != dns.rdatatype.RRSIG and rr.rdtype != dns.rdatatype.DNSKEY:
            sigs = utils.get_rrsig_for_rr(zone.RR, rr)
            msg = Message(zone.name, rr.name, rr.rdtype)
            if sigs:
                for sig in sigs:
                    try:
                        dns.dnssec.validate_rrsig(
                            rr, sig, {dns.name.from_text(zone.name): zsks},
                        )
                    except dns.dnssec.ValidationFailure as e:
                        msg.add_warning(
                            Validator.ZSK,
                            sig.key_tag,
                            f"{Msg.VALIDATION_FAILURE} ({e})",
                        )
                    else:
                        msg.set_success(Validator.ZSK, sig.key_tag)
            else:
                msg.set_not_found(Msg.RRSIG_NOT_FOUND)

            s = result.compute_message(msg)
            result.change_state(s)
            res &= s
            if save and msg:
                result.secure_rrsets.append(rr)
                result.note += f" {dns.rdatatype.to_text(rr.rdtype)},"
            elif save:
                result.insecure_rrsets.append(rr)
                result.note += f" {dns.rdatatype.to_text(rr.rdtype)}*,"

    # post processing of DNSSECScannerResult note variable for pretty printing
    if save:
        result.note = result.note[:-1]

    return res
