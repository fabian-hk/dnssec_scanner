import logging

import dns.rdatatype

from tests.utils.custom_test_case import CustomTestCase as CTC
from dnssec_scanner import DNSSECScanner, State
from dnssec_scanner.messages import Validator, Msg, Types
from tests.utils.messages_testing import TestMessage

log = logging.getLogger("dnssec_scanner")
log.setLevel(logging.WARNING)


class GoogleCom(CTC):
    """
    Last checked on 11.04.2020
    """

    # fmt: off
    LOGS = [
        str(TestMessage(".", "", Types.KSK, CTC.SINGLE_PATTERN, Msg.VALIDATED, Validator.DS, CTC.SINGLE_PATTERN)),
        str(TestMessage(".", "", dns.rdatatype.DNSKEY, CTC.MULTI_PATTERN, Msg.VALIDATED, Validator.KSK,
                        CTC.SINGLE_PATTERN)),
        str(TestMessage(".", "com.", dns.rdatatype.DS, CTC.MULTI_PATTERN, Msg.VALIDATED, Validator.ZSK,
                        CTC.SINGLE_PATTERN)),
        str(TestMessage("com.", "", Types.KSK, CTC.SINGLE_PATTERN, Msg.VALIDATED, Validator.DS, CTC.SINGLE_PATTERN)),
        str(TestMessage("com.", "", dns.rdatatype.DNSKEY, CTC.MULTI_PATTERN, Msg.VALIDATED, Validator.KSK,
                        CTC.SINGLE_PATTERN)),
        str(TestMessage("com.", "CK0POJMG874LJREF7EFN8430QVIT8BSM.com.", dns.rdatatype.NSEC3, "", Msg.VALIDATED,
                        Validator.ZSK, CTC.SINGLE_PATTERN)),
        str(TestMessage("com.", "com.", dns.rdatatype.SOA, "", Msg.VALIDATED, Validator.ZSK, CTC.SINGLE_PATTERN)),
        str(TestMessage("com.", "S84BDVKNH5AGDSI7F5J0O3NPRHU0G7JQ.com.", dns.rdatatype.NSEC3, "", Msg.VALIDATED,
                        Validator.ZSK, CTC.SINGLE_PATTERN)),
        str(TestMessage("com.", "com.", dns.rdatatype.NSEC3PARAM, "", Msg.VALIDATED, Validator.ZSK,
                        CTC.SINGLE_PATTERN)),
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
        result = scanner.run()

        self.assert_list(self.LOGS, result.logs)
        self.assert_list(self.WARNIGNS, result.warnings)
        self.assert_list(self.ERRORS, result.errors)

        self.assertEqual(State.INSECURE, result.state)
