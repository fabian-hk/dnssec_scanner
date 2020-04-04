import unittest
import logging

import dns.rdatatype

from dnssec_scanner import DNSSECScanner, State
from dnssec_scanner.messages import Validator, Msg, Types
from tests.messages_testing import TestMessage

log = logging.getLogger("dnssec_scanner")
log.setLevel(logging.WARNING)


class RhybarCz(unittest.TestCase):
    """
    Last checked on 04.04.2020
    """

    # fmt: off
    LOGS = [
        str(TestMessage(".", "", Types.KSK, "20326", Msg.VALIDATED, Validator.DS, "20326")),
        str(TestMessage(".", "", dns.rdatatype.DNSKEY, "20326,33853,48903", Msg.VALIDATED, Validator.KSK, "20326")),
        str(TestMessage(".", "cz.", dns.rdatatype.DS, "20237", Msg.VALIDATED, Validator.ZSK, "48903")),
        str(TestMessage("cz.", "", Types.KSK, "20237", Msg.VALIDATED, Validator.DS, "20237")),
        str(TestMessage("cz.", "", dns.rdatatype.DNSKEY, "16513,20237,44987", Msg.VALIDATED, Validator.KSK, "20237")),
        str(TestMessage("cz.", "", dns.rdatatype.DNSKEY, "16513,20237,44987", Msg.VALIDATED, Validator.ZSK, "44987")),
        str(TestMessage("cz.", "rhybar.cz.", dns.rdatatype.DS, "61281", Msg.VALIDATED, Validator.ZSK, "44987")),
    ]

    WARNIGNS = []

    ERRORS = [
        str(TestMessage("rhybar.cz.", "", Types.KSK, "44566", Msg.DS_NOT_FOUND, "", "")),
        "rhybar.cz. zone: Could not validate any KSK",
        "rhybar.cz. zone: Could not validate DNSKEY with a trusted KSK",
        str(TestMessage("rhybar.cz.", "", dns.rdatatype.DNSKEY, "5172,34392,44566",
                        f"{Msg.VALIDATION_FAILURE} (expired)", Validator.UNTRUSTED_KSK, "44566")),
        str(TestMessage("rhybar.cz.", "", dns.rdatatype.DNSKEY, "5172,34392,44566",
                        f"{Msg.VALIDATION_FAILURE} (expired)", Validator.ZSK, "5172")),
        str(TestMessage("rhybar.cz.", "rhybar.cz.", dns.rdatatype.NS, "", f"{Msg.VALIDATION_FAILURE} (expired)",
                        Validator.ZSK, "5172")),
        str(TestMessage("rhybar.cz.", "rhybar.cz.", dns.rdatatype.SOA, "", f"{Msg.VALIDATION_FAILURE} (expired)",
                        Validator.ZSK, "5172")),
        str(TestMessage("rhybar.cz.", "rhybar.cz.", dns.rdatatype.MX, "", Msg.RRSIG_NOT_FOUND, "", "")),
        str(TestMessage("rhybar.cz.", "rhybar.cz.", dns.rdatatype.NSEC, "", f"{Msg.VALIDATION_FAILURE} (expired)",
                        Validator.ZSK, "5172")),
    ]

    # fmt: on

    def test_dnssec(self):
        scanner = DNSSECScanner("rhybar.cz")
        result = scanner.run_scan()

        self.assertCountEqual(self.LOGS, result.logs)
        self.assertCountEqual(self.WARNIGNS, result.warnings)
        self.assertCountEqual(self.ERRORS, result.errors)

        self.assertEqual(State.BOGUS, result.state)


class RhybarCzNonExistence(unittest.TestCase):
    """
    Last checked on 04.04.2020
    """

    # fmt: off
    LOGS = [
        str(TestMessage(".", "", Types.KSK, "20326", Msg.VALIDATED, Validator.DS, "20326")),
        str(TestMessage(".", "", dns.rdatatype.DNSKEY, "20326,33853,48903", Msg.VALIDATED, Validator.KSK, "20326")),
        str(TestMessage(".", "cz.", dns.rdatatype.DS, "20237", Msg.VALIDATED, Validator.ZSK, "48903")),
        str(TestMessage("cz.", "", Types.KSK, "20237", Msg.VALIDATED, Validator.DS, "20237")),
        str(TestMessage("cz.", "", dns.rdatatype.DNSKEY, "16513,20237,44987", Msg.VALIDATED, Validator.KSK, "20237")),
        str(TestMessage("cz.", "", dns.rdatatype.DNSKEY, "16513,20237,44987", Msg.VALIDATED, Validator.ZSK, "44987")),
        str(TestMessage("cz.", "rhybar.cz.", dns.rdatatype.DS, "61281", Msg.VALIDATED, Validator.ZSK, "44987")),
        "rhybar.cz. zone: Found NSEC that a.rhybar.cz does not exist",
        "rhybar.cz. zone: Found NSEC that no wildcard expansion for a.rhybar.cz is possible",
    ]

    WARNIGNS = []

    ERRORS = [
        str(TestMessage("rhybar.cz.", "", Types.KSK, "44566", Msg.DS_NOT_FOUND, "", "")),
        "rhybar.cz. zone: Could not validate any KSK",
        "rhybar.cz. zone: Could not validate DNSKEY with a trusted KSK",
        str(TestMessage("rhybar.cz.", "", dns.rdatatype.DNSKEY, "5172,34392,44566",
                        f"{Msg.VALIDATION_FAILURE} (expired)", Validator.UNTRUSTED_KSK, "44566")),
        str(TestMessage("rhybar.cz.", "", dns.rdatatype.DNSKEY, "5172,34392,44566",
                        f"{Msg.VALIDATION_FAILURE} (expired)", Validator.ZSK, "5172")),
        str(TestMessage("rhybar.cz.", "rhybar.cz.", dns.rdatatype.SOA, "", f"{Msg.VALIDATION_FAILURE} (expired)",
                        Validator.ZSK, "5172")),
        str(TestMessage("rhybar.cz.", "rhybar.cz.", dns.rdatatype.NSEC, "", f"{Msg.VALIDATION_FAILURE} (expired)",
                        Validator.ZSK, "5172")),
    ]

    # fmt: on

    def test_dnssec(self):
        scanner = DNSSECScanner("a.rhybar.cz")
        result = scanner.run_scan()

        self.assertCountEqual(self.LOGS, result.logs)
        self.assertCountEqual(self.WARNIGNS, result.warnings)
        self.assertCountEqual(self.ERRORS, result.errors)

        self.assertEqual(State.BOGUS, result.state)
