import unittest
import logging

import dns.rdatatype

from dnssec_scanner import DNSSECScanner, State
from dnssec_scanner.messages import Validator, Msg, Types
from tests.messages_testing import TestMessage

log = logging.getLogger("dnssec_scanner")
log.setLevel(logging.WARNING)


class WwwIetfOrg(unittest.TestCase):
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
        str(TestMessage("org.", "ietf.org.", dns.rdatatype.DS, "45586,45586", Msg.VALIDATED, Validator.ZSK, "37022")),
        str(TestMessage("ietf.org.", "", Types.KSK, "45586", Msg.VALIDATED, Validator.DS, "45586")),
        str(TestMessage("ietf.org.", "", dns.rdatatype.DNSKEY, "40452,45586", Msg.VALIDATED, Validator.KSK, "45586")),
        str(TestMessage("ietf.org.", "", dns.rdatatype.DNSKEY, "40452,45586", Msg.VALIDATED, Validator.ZSK, "40452")),
        str(TestMessage("ietf.org.", "www.ietf.org.", dns.rdatatype.CNAME, "", Msg.VALIDATED, Validator.ZSK, "40452")),
        str(TestMessage(".", "", Types.KSK, "20326", Msg.VALIDATED, Validator.DS, "20326")),
        str(TestMessage(".", "", dns.rdatatype.DNSKEY, "20326,33853,48903", Msg.VALIDATED, Validator.KSK, "20326")),
        str(TestMessage(".", "net.", dns.rdatatype.DS, "35886", Msg.VALIDATED, Validator.ZSK, "48903")),
        str(TestMessage("net.", "", Types.KSK, "35886", Msg.VALIDATED, Validator.DS, "35886")),
        str(TestMessage("net.", "", dns.rdatatype.DNSKEY, "24512,35886", Msg.VALIDATED, Validator.KSK, "35886")),
        str(TestMessage("net.", "cloudflare.net.", dns.rdatatype.DS, "2371", Msg.VALIDATED, Validator.ZSK, "24512")),
        str(TestMessage("cloudflare.net.", "", Types.KSK, "2371", Msg.VALIDATED, Validator.DS, "2371")),
        str(TestMessage("cloudflare.net.", "", dns.rdatatype.DNSKEY, "2371,34505", Msg.VALIDATED, Validator.KSK,
                        "2371")),
        str(TestMessage("cloudflare.net.", "www.ietf.org.cdn.cloudflare.net.", dns.rdatatype.A, "", Msg.VALIDATED,
                        Validator.ZSK, "34505")),
        str(TestMessage("cloudflare.net.", "www.ietf.org.cdn.cloudflare.net.", dns.rdatatype.AAAA, "", Msg.VALIDATED,
                        Validator.ZSK, "34505")),
    ]

    WARNIGNS = []

    ERRORS = []

    # fmt: on

    def test_dnssec(self):
        scanner = DNSSECScanner("www.ietf.org")
        result = scanner.run_scan()

        self.assertCountEqual(self.LOGS, result.logs)
        self.assertCountEqual(self.WARNIGNS, result.warnings)
        self.assertCountEqual(self.ERRORS, result.errors)

        self.assertEqual(State.SECURE, result.state)
