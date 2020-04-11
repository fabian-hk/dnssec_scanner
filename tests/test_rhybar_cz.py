import logging

import dns.rdatatype

from tests.utils.custom_test_case import CustomTestCase as CTC
from dnssec_scanner import DNSSECScanner, State
from dnssec_scanner.messages import Validator, Msg, Types
from tests.utils.messages_testing import TestMessage

log = logging.getLogger("dnssec_scanner")
log.setLevel(logging.WARNING)


class RhybarCz(CTC):
    """
    Last checked on 11.04.2020
    """

    # fmt: off
    LOGS = [
        str(TestMessage(".", "", Types.KSK, CTC.SINGLE_PATTERN, Msg.VALIDATED, Validator.DS, CTC.SINGLE_PATTERN)),
        str(TestMessage(".", "", dns.rdatatype.DNSKEY, CTC.MULTI_PATTERN, Msg.VALIDATED, Validator.KSK,
                        CTC.SINGLE_PATTERN)),
        str(TestMessage(".", "cz.", dns.rdatatype.DS, CTC.MULTI_PATTERN, Msg.VALIDATED, Validator.ZSK,
                        CTC.SINGLE_PATTERN)),
        str(TestMessage("cz.", "", Types.KSK, CTC.SINGLE_PATTERN, Msg.VALIDATED, Validator.DS, CTC.SINGLE_PATTERN)),
        str(TestMessage("cz.", "", dns.rdatatype.DNSKEY, CTC.MULTI_PATTERN, Msg.VALIDATED, Validator.KSK,
                        CTC.SINGLE_PATTERN)),
        str(TestMessage("cz.", "", dns.rdatatype.DNSKEY, CTC.MULTI_PATTERN, Msg.VALIDATED, Validator.ZSK,
                        CTC.SINGLE_PATTERN)),
        str(TestMessage("cz.", "rhybar.cz.", dns.rdatatype.DS, CTC.MULTI_PATTERN, Msg.VALIDATED, Validator.ZSK,
                        CTC.SINGLE_PATTERN)),
    ]

    WARNIGNS = []

    ERRORS = [
        str(TestMessage("rhybar.cz.", "", Types.KSK, CTC.SINGLE_PATTERN, Msg.DS_NOT_FOUND, "", "")),
        "rhybar.cz. zone: Could not validate any KSK",
        "rhybar.cz. zone: Could not validate DNSKEY with a trusted KSK",
        str(TestMessage("rhybar.cz.", "", dns.rdatatype.DNSKEY, CTC.MULTI_PATTERN,
                        f"{Msg.VALIDATION_FAILURE} \(expired\)", Validator.UNTRUSTED_KSK, CTC.SINGLE_PATTERN)),
        str(TestMessage("rhybar.cz.", "", dns.rdatatype.DNSKEY, CTC.MULTI_PATTERN,
                        f"{Msg.VALIDATION_FAILURE} \(expired\)", Validator.ZSK, CTC.SINGLE_PATTERN)),
        str(TestMessage("rhybar.cz.", "rhybar.cz.", dns.rdatatype.NS, "", f"{Msg.VALIDATION_FAILURE} \(expired\)",
                        Validator.ZSK, CTC.SINGLE_PATTERN)),
        str(TestMessage("rhybar.cz.", "rhybar.cz.", dns.rdatatype.SOA, "", f"{Msg.VALIDATION_FAILURE} \(expired\)",
                        Validator.ZSK, CTC.SINGLE_PATTERN)),
        str(TestMessage("rhybar.cz.", "rhybar.cz.", dns.rdatatype.MX, "", Msg.RRSIG_NOT_FOUND, "", "")),
        str(TestMessage("rhybar.cz.", "rhybar.cz.", dns.rdatatype.NSEC, "", f"{Msg.VALIDATION_FAILURE} \(expired\)",
                        Validator.ZSK, CTC.SINGLE_PATTERN)),
    ]

    # fmt: on

    def test_dnssec(self):
        scanner = DNSSECScanner("rhybar.cz")
        result = scanner.run()

        self.assert_list(self.LOGS, result.logs)
        self.assert_list(self.WARNIGNS, result.warnings)
        self.assert_list(self.ERRORS, result.errors)

        self.assertEqual(State.BOGUS, result.state)


class RhybarCzNonExistence(CTC):
    """
    Last checked on 11.04.2020
    """

    # fmt: off
    LOGS = [
        str(TestMessage(".", "", Types.KSK, CTC.SINGLE_PATTERN, Msg.VALIDATED, Validator.DS, CTC.SINGLE_PATTERN)),
        str(TestMessage(".", "", dns.rdatatype.DNSKEY, CTC.MULTI_PATTERN, Msg.VALIDATED, Validator.KSK,
                        CTC.SINGLE_PATTERN)),
        str(TestMessage(".", "cz.", dns.rdatatype.DS, CTC.MULTI_PATTERN, Msg.VALIDATED, Validator.ZSK,
                        CTC.SINGLE_PATTERN)),
        str(TestMessage("cz.", "", Types.KSK, CTC.SINGLE_PATTERN, Msg.VALIDATED, Validator.DS, CTC.SINGLE_PATTERN)),
        str(TestMessage("cz.", "", dns.rdatatype.DNSKEY, CTC.MULTI_PATTERN, Msg.VALIDATED, Validator.KSK,
                        CTC.SINGLE_PATTERN)),
        str(TestMessage("cz.", "", dns.rdatatype.DNSKEY, CTC.MULTI_PATTERN, Msg.VALIDATED, Validator.ZSK,
                        CTC.SINGLE_PATTERN)),
        str(TestMessage("cz.", "rhybar.cz.", dns.rdatatype.DS, CTC.MULTI_PATTERN, Msg.VALIDATED, Validator.ZSK,
                        CTC.SINGLE_PATTERN)),
        "rhybar.cz. zone: Found NSEC that a.rhybar.cz does not exist",
        "rhybar.cz. zone: Found NSEC that no wildcard expansion for a.rhybar.cz is possible",
    ]

    WARNIGNS = []

    ERRORS = [
        str(TestMessage("rhybar.cz.", "", Types.KSK, CTC.SINGLE_PATTERN, Msg.DS_NOT_FOUND, "", "")),
        "rhybar.cz. zone: Could not validate any KSK",
        "rhybar.cz. zone: Could not validate DNSKEY with a trusted KSK",
        str(TestMessage("rhybar.cz.", "", dns.rdatatype.DNSKEY, CTC.MULTI_PATTERN,
                        f"{Msg.VALIDATION_FAILURE} \(expired\)", Validator.UNTRUSTED_KSK, CTC.SINGLE_PATTERN)),
        str(TestMessage("rhybar.cz.", "", dns.rdatatype.DNSKEY, CTC.MULTI_PATTERN,
                        f"{Msg.VALIDATION_FAILURE} \(expired\)", Validator.ZSK, CTC.SINGLE_PATTERN)),
        str(TestMessage("rhybar.cz.", "rhybar.cz.", dns.rdatatype.SOA, "", f"{Msg.VALIDATION_FAILURE} \(expired\)",
                        Validator.ZSK, CTC.SINGLE_PATTERN)),
        str(TestMessage("rhybar.cz.", "rhybar.cz.", dns.rdatatype.NSEC, "", f"{Msg.VALIDATION_FAILURE} \(expired\)",
                        Validator.ZSK, CTC.SINGLE_PATTERN)),
    ]

    # fmt: on

    def test_dnssec(self):
        scanner = DNSSECScanner("a.rhybar.cz")
        result = scanner.run()

        self.assert_list(self.LOGS, result.logs)
        self.assert_list(self.WARNIGNS, result.warnings)
        self.assert_list(self.ERRORS, result.errors)

        self.assertEqual(State.BOGUS, result.state)
