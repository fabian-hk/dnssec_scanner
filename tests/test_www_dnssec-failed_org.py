import unittest
import logging

import dns.rdatatype

from dnssec_scanner import DNSSECScanner, State
from dnssec_scanner.messages import Validator, Msg, Types
from tests.messages_testing import TestMessage

log = logging.getLogger("dnssec_scanner")
log.setLevel(logging.WARNING)


class WwwDnssecFailedOrg(unittest.TestCase):
    """
    Last checked on 09.04.2020
    """

    # fmt: off
    LOGS = [
        str(TestMessage(".", "", Types.KSK, "20326", Msg.VALIDATED, Validator.DS, "20326")),
        str(TestMessage(".", "", dns.rdatatype.DNSKEY, "20326,33853,48903", Msg.VALIDATED, Validator.KSK, "20326")),
        str(TestMessage(".", "org.", dns.rdatatype.DS, "9795,9795", Msg.VALIDATED, Validator.ZSK, "48903")),
        str(TestMessage("org.", "", Types.KSK, "9795", Msg.VALIDATED, Validator.DS, "9795")),
        str(TestMessage("org.", "", dns.rdatatype.DNSKEY, "9795,17883,33209,37022", Msg.VALIDATED, Validator.KSK,
                        "9795")),
        str(TestMessage("org.", "", dns.rdatatype.DNSKEY, "9795,17883,33209,37022", Msg.VALIDATED, Validator.KSK,
                        "17883")),
        str(TestMessage("org.", "", dns.rdatatype.DNSKEY, "9795,17883,33209,37022", Msg.VALIDATED, Validator.ZSK,
                        "37022")),
        str(TestMessage("org.", "dnssec-failed.org.", dns.rdatatype.DS, "106,106", Msg.VALIDATED, Validator.ZSK,
                        "37022")),
        str(TestMessage("dnssec-failed.org.", "", dns.rdatatype.DNSKEY, "29521,44973", Msg.VALIDATED, Validator.ZSK,
                        "44973")),
        str(TestMessage("dnssec-failed.org.", "www.dnssec-failed.org.", dns.rdatatype.A, "", Msg.VALIDATED,
                        Validator.ZSK, "44973")),
        str(TestMessage("dnssec-failed.org.", "www.dnssec-failed.org.", dns.rdatatype.TXT, "", Msg.VALIDATED,
                        Validator.ZSK, "44973")),
        str(TestMessage("dnssec-failed.org.", "www.dnssec-failed.org.", dns.rdatatype.NSEC, "", Msg.VALIDATED,
                        Validator.ZSK, "44973")),
    ]

    WARNIGNS = []

    ERRORS = [
        str(TestMessage("dnssec-failed.org.", "", Types.KSK, "29521", Msg.DS_NOT_FOUND, "", "")),
        "dnssec-failed.org. zone: Could not validate any KSK",
        "dnssec-failed.org. zones: Could not validate DNSKEY with a trusted KSK",
        str(TestMessage("dnssec-failed.org.", "", dns.rdatatype.DNSKEY, "29521,44973", Msg.VALIDATED,
                        Validator.UNTRUSTED_KSK, "29521")),
    ]

    # fmt: on

    def test_dnssec(self):
        scanner = DNSSECScanner("www.dnssec-failed.org")
        result = scanner.run_scan()

        self.assertCountEqual(self.LOGS, result.logs)
        self.assertCountEqual(self.WARNIGNS, result.warnings)
        self.assertCountEqual(self.ERRORS, result.errors)

        self.assertEqual(State.BOGUS, result.state)
