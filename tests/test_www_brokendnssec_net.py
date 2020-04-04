import unittest
import logging

import dns.rdatatype

from dnssec_scanner import DNSSECScanner, State
from dnssec_scanner.messages import Validator, Msg, Types
from tests.messages_testing import TestMessage

log = logging.getLogger("dnssec_scanner")
log.setLevel(logging.WARNING)


class WwwBrokendnssecNet(unittest.TestCase):
    """
    Last checked on 04.04.2020
    """

    # fmt: off
    LOGS = [
        str(TestMessage(".", "", Types.KSK, "20326", Msg.VALIDATED, Validator.DS, "20326")),
        str(TestMessage(".", "", dns.rdatatype.DNSKEY, "20326,33853,48903", Msg.VALIDATED, Validator.KSK, "20326")),
        str(TestMessage(".", "net.", dns.rdatatype.DS, "35886", Msg.VALIDATED, Validator.ZSK, "48903")),
        str(TestMessage("net.", "", Types.KSK, "35886", Msg.VALIDATED, Validator.DS, "35886")),
        str(TestMessage("net.", "", dns.rdatatype.DNSKEY, "24512,35886", Msg.VALIDATED, Validator.KSK, "35886")),
        str(TestMessage("net.", "brokendnssec.net.", dns.rdatatype.DS, "2371", Msg.VALIDATED, Validator.ZSK, "24512")),
    ]

    WARNIGNS = []

    ERRORS = [
        str(TestMessage("brokendnssec.net.", "", dns.rdatatype.DNSKEY, "", Msg.NOT_FOUND, "", "")),
        str(TestMessage("brokendnssec.net.", "", dns.rdatatype.DNSKEY, "", Msg.RRSIG_NOT_FOUND, "", "")),
        str(TestMessage("brokendnssec.net.", "www.brokendnssec.net.", dns.rdatatype.A, "", Msg.RRSIG_NOT_FOUND, "",
                        "")),
    ]

    # fmt: on

    def test_dnssec(self):
        scanner = DNSSECScanner("www.brokendnssec.net")
        result = scanner.run_scan()

        self.assertCountEqual(self.LOGS, result.logs)
        self.assertCountEqual(self.WARNIGNS, result.warnings)
        self.assertCountEqual(self.ERRORS, result.errors)

        self.assertEqual(State.BOGUS, result.state)
