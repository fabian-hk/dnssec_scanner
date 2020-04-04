import unittest
import logging

import dns.rdatatype

from dnssec_scanner import DNSSECScanner, State
from dnssec_scanner.messages import Validator, Msg, Types
from tests.messages_testing import TestMessage

log = logging.getLogger("dnssec_scanner")
log.setLevel(logging.WARNING)


class GoogleCom(unittest.TestCase):
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
        str(TestMessage("com.", "CK0POJMG874LJREF7EFN8430QVIT8BSM.com.", dns.rdatatype.NSEC3, "", Msg.VALIDATED,
                        Validator.ZSK, "56311")),
        str(TestMessage("com.", "com.", dns.rdatatype.SOA, "", Msg.VALIDATED, Validator.ZSK, "56311")),
        str(TestMessage("com.", "S84BDVKNH5AGDSI7F5J0O3NPRHU0G7JQ.com.", dns.rdatatype.NSEC3, "", Msg.VALIDATED,
                        Validator.ZSK, "56311")),
        str(TestMessage("com.", "com.", dns.rdatatype.NSEC3PARAM, "", Msg.VALIDATED, Validator.ZSK, "56311")),
        "com. zone: Found closest encloser com.",
        "com. zone: Found NSEC3 that covers the next closer name google.com.",
        "com. zone: Successfully proved that google.com. does not support DNSSEC",
    ]

    WARNIGNS = []

    ERRORS = [
        str(TestMessage("com.", "google.com.", dns.rdatatype.DS, "", Msg.NOT_FOUND, "", "")),
        str(TestMessage("google.com.", "", dns.rdatatype.DNSKEY, "", Msg.NOT_FOUND, "", "")),
        str(TestMessage("google.com.", "", dns.rdatatype.DNSKEY, "", Msg.RRSIG_NOT_FOUND, "", "")),
        str(TestMessage("google.com.", "google.com.", dns.rdatatype.A, "", Msg.RRSIG_NOT_FOUND, "", "")),
        str(TestMessage("google.com.", "google.com.", dns.rdatatype.NS, "", Msg.RRSIG_NOT_FOUND, "", "")),
        str(TestMessage("google.com.", "google.com.", dns.rdatatype.CAA, "", Msg.RRSIG_NOT_FOUND, "", "")),
        str(TestMessage("google.com.", "google.com.", dns.rdatatype.SOA, "", Msg.RRSIG_NOT_FOUND, "", "")),
        str(TestMessage("google.com.", "google.com.", dns.rdatatype.MX, "", Msg.RRSIG_NOT_FOUND, "", "")),
        str(TestMessage("google.com.", "google.com.", dns.rdatatype.TXT, "", Msg.RRSIG_NOT_FOUND, "", "")),
        str(TestMessage("google.com.", "google.com.", dns.rdatatype.AAAA, "", Msg.RRSIG_NOT_FOUND, "", "")),
    ]

    # fmt: on

    def test_dnssec(self):
        scanner = DNSSECScanner("google.com")
        result = scanner.run_scan()

        self.assertCountEqual(self.LOGS, result.logs)
        self.assertCountEqual(self.WARNIGNS, result.warnings)
        self.assertCountEqual(self.ERRORS, result.errors)

        self.assertEqual(State.INSECURE, result.state)
