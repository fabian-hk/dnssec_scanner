import unittest
import logging

import dns.rdatatype

from dnssec_scanner import DNSSECScanner, State
from dnssec_scanner.messages import Validator, Msg, Types
from tests.messages_testing import TestMessage

log = logging.getLogger("dnssec_scanner")
log.setLevel(logging.WARNING)


class YesCom(unittest.TestCase):
    """
    Last checked on 04.04.2020
    """

    # fmt: off
    LOGS = [
        str(TestMessage(".", "", Types.KSK, "20326", Msg.VALIDATED, Validator.DS, "20326")),
        str(TestMessage(".", "", dns.rdatatype.DNSKEY, "20326,33853,48903", Msg.VALIDATED, Validator.KSK, "20326")),
        str(TestMessage(".", "com.", dns.rdatatype.DS, "30909", Msg.VALIDATED, Validator.ZSK, "48903")),
        str(TestMessage("com.", "", Types.KSK, "30909", Msg.VALIDATED, Validator.DS, "30909")),
        str(TestMessage("com.", "", dns.rdatatype.DNSKEY, "30909,56311", Msg.VALIDATED, Validator.KSK, "30909")),
        str(TestMessage("com.", "yes.com.", dns.rdatatype.DS, "54547", Msg.VALIDATED, Validator.ZSK, "56311")),
        str(TestMessage("yes.com.", "", Types.KSK, "54547", Msg.VALIDATED, Validator.DS, "54547")),
        str(TestMessage("yes.com.", "", dns.rdatatype.DNSKEY, "47238,54547", Msg.VALIDATED, Validator.KSK, "54547")),
        str(TestMessage("yes.com.", "", dns.rdatatype.DNSKEY, "47238,54547", Msg.VALIDATED, Validator.ZSK, "47238")),
        str(TestMessage("yes.com.", "yes.com.", dns.rdatatype.A, "", Msg.VALIDATED, Validator.ZSK, "47238")),
        str(TestMessage("yes.com.", "yes.com.", dns.rdatatype.NS, "", Msg.VALIDATED, Validator.ZSK, "47238")),
        str(TestMessage("yes.com.", "yes.com.", dns.rdatatype.CAA, "", Msg.VALIDATED, Validator.ZSK, "47238")),
        str(TestMessage("yes.com.", "yes.com.", dns.rdatatype.SOA, "", Msg.VALIDATED, Validator.ZSK, "47238")),
        str(TestMessage("yes.com.", "yes.com.", dns.rdatatype.MX, "", Msg.VALIDATED, Validator.ZSK, "47238")),
        str(TestMessage("yes.com.", "yes.com.", dns.rdatatype.TXT, "", Msg.VALIDATED, Validator.ZSK, "47238")),
        str(TestMessage("yes.com.", "yes.com.", "TYPE65534", "", Msg.VALIDATED, Validator.ZSK, "47238")),
    ]

    WARNIGNS = []

    ERRORS = []

    # fmt: on

    def test_dnssec(self):
        scanner = DNSSECScanner("yes.com")
        result = scanner.run_scan()

        self.assertCountEqual(self.LOGS, result.logs)
        self.assertCountEqual(self.WARNIGNS, result.warnings)
        self.assertCountEqual(self.ERRORS, result.errors)

        self.assertEqual(State.SECURE, result.state)


class YesComNonExistence(unittest.TestCase):
    """
    Last checked on 04.04.2020
    """

    # fmt: off
    LOGS = [
        str(TestMessage(".", "", Types.KSK, "20326", Msg.VALIDATED, Validator.DS, "20326")),
        str(TestMessage(".", "", dns.rdatatype.DNSKEY, "20326,33853,48903", Msg.VALIDATED, Validator.KSK, "20326")),
        str(TestMessage(".", "com.", dns.rdatatype.DS, "30909", Msg.VALIDATED, Validator.ZSK, "48903")),
        str(TestMessage("com.", "", Types.KSK, "30909", Msg.VALIDATED, Validator.DS, "30909")),
        str(TestMessage("com.", "", dns.rdatatype.DNSKEY, "30909,56311", Msg.VALIDATED, Validator.KSK, "30909")),
        str(TestMessage("com.", "yes.com.", dns.rdatatype.DS, "54547", Msg.VALIDATED, Validator.ZSK, "56311")),
        str(TestMessage("yes.com.", "", Types.KSK, "54547", Msg.VALIDATED, Validator.DS, "54547")),
        str(TestMessage("yes.com.", "", dns.rdatatype.DNSKEY, "47238,54547", Msg.VALIDATED, Validator.KSK, "54547")),
        str(TestMessage("yes.com.", "", dns.rdatatype.DNSKEY, "47238,54547", Msg.VALIDATED, Validator.ZSK, "47238")),
        str(TestMessage("yes.com.", "yes.com.", dns.rdatatype.SOA, "", Msg.VALIDATED, Validator.ZSK, "47238")),
        str(TestMessage("yes.com.", "je1edi9is5n65eb2lspgaqnvj1nntaf2.yes.com.", dns.rdatatype.NSEC3, "", Msg.VALIDATED,
                        Validator.ZSK, "47238")),
        str(TestMessage("yes.com.", "rpurinq1i0tkg5bjgm833tr3sfphj2t2.yes.com.", dns.rdatatype.NSEC3, "", Msg.VALIDATED,
                        Validator.ZSK, "47238")),
        str(TestMessage("yes.com.", "9ervkmn64tv9jn6fukbafanu49478opv.yes.com.", dns.rdatatype.NSEC3, "", Msg.VALIDATED,
                        Validator.ZSK, "47238")),
        str(TestMessage("yes.com.", "yes.com.", dns.rdatatype.NSEC3PARAM, "", Msg.VALIDATED, Validator.ZSK, "47238")),
        "yes.com. zone: Found closest encloser yes.com.",
        "yes.com. zone: Found NSEC3 that covers the next closer name a.yes.com.",
        "yes.com. zone: Found NSEC3 that covers the wildcard *.yes.com."
    ]

    WARNIGNS = []

    ERRORS = []

    # fmt: on

    def test_dnssec(self):
        scanner = DNSSECScanner("a.yes.com")
        result = scanner.run_scan()

        self.assertCountEqual(self.LOGS, result.logs)
        self.assertCountEqual(self.WARNIGNS, result.warnings)
        self.assertCountEqual(self.ERRORS, result.errors)

        self.assertEqual(State.SECURE, result.state)
