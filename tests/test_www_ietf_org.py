import logging

import dns.rdatatype
import re

from tests.utils.custom_test_case import CustomTestCase as CTC
from dnssec_scanner import DNSSECScanner, State
from dnssec_scanner.messages import Validator, Msg, Types
from tests.utils.messages_testing import TestMessage

log = logging.getLogger("dnssec_scanner")
log.setLevel(logging.WARNING)


class WwwIetfOrg(CTC):

    # fmt: off
    LOGS = [
        str(TestMessage(".", "", Types.KSK, CTC.MULTI_PATTERN, Msg.VALIDATED, Validator.DS, CTC.SINGLE_PATTERN)),
        str(TestMessage(".", "", dns.rdatatype.DNSKEY, CTC.MULTI_PATTERN, Msg.VALIDATED, Validator.KSK,
                        CTC.SINGLE_PATTERN)),
        str(TestMessage(".", "org.", dns.rdatatype.DS, CTC.MULTI_PATTERN, Msg.VALIDATED, Validator.ZSK,
                        CTC.SINGLE_PATTERN)),
        str(TestMessage("org.", "", Types.KSK, CTC.SINGLE_PATTERN, Msg.VALIDATED, Validator.DS, CTC.SINGLE_PATTERN)),
        str(TestMessage("org.", "", Types.KSK, CTC.SINGLE_PATTERN, Msg.VALIDATED, Validator.DS, CTC.SINGLE_PATTERN)),
        str(TestMessage("org.", "", dns.rdatatype.DNSKEY, CTC.MULTI_PATTERN, Msg.VALIDATED, Validator.KSK,
                        CTC.SINGLE_PATTERN)),
        str(TestMessage("org.", "", dns.rdatatype.DNSKEY, CTC.MULTI_PATTERN, Msg.VALIDATED, Validator.KSK,
                        CTC.SINGLE_PATTERN)),
        str(TestMessage("org.", "", dns.rdatatype.DNSKEY, CTC.MULTI_PATTERN, Msg.VALIDATED, Validator.ZSK,
                        CTC.SINGLE_PATTERN)),
        str(TestMessage("org.", "ietf.org.", dns.rdatatype.DS, CTC.MULTI_PATTERN, Msg.VALIDATED, Validator.ZSK,
                        CTC.SINGLE_PATTERN)),
        str(TestMessage("ietf.org.", "", Types.KSK, CTC.SINGLE_PATTERN, Msg.VALIDATED, Validator.DS,
                        CTC.SINGLE_PATTERN)),
        str(TestMessage("ietf.org.", "", dns.rdatatype.DNSKEY, CTC.MULTI_PATTERN, Msg.VALIDATED, Validator.KSK,
                        CTC.SINGLE_PATTERN)),
        str(TestMessage("ietf.org.", "", dns.rdatatype.DNSKEY, CTC.MULTI_PATTERN, Msg.VALIDATED, Validator.ZSK,
                        CTC.SINGLE_PATTERN)),
        str(TestMessage("ietf.org.", "www.ietf.org.", dns.rdatatype.CNAME, "", Msg.VALIDATED, Validator.ZSK,
                        CTC.SINGLE_PATTERN)),
        str(TestMessage(".", "", Types.KSK, CTC.SINGLE_PATTERN, Msg.VALIDATED, Validator.DS, CTC.SINGLE_PATTERN)),
        str(TestMessage(".", "", dns.rdatatype.DNSKEY, CTC.MULTI_PATTERN, Msg.VALIDATED, Validator.KSK,
                        CTC.SINGLE_PATTERN)),
        str(TestMessage(".", "net.", dns.rdatatype.DS, CTC.MULTI_PATTERN, Msg.VALIDATED, Validator.ZSK,
                        CTC.SINGLE_PATTERN)),
        str(TestMessage("net.", "", Types.KSK, CTC.SINGLE_PATTERN, Msg.VALIDATED, Validator.DS, CTC.SINGLE_PATTERN)),
        str(TestMessage("net.", "", dns.rdatatype.DNSKEY, CTC.MULTI_PATTERN, Msg.VALIDATED, Validator.KSK,
                        CTC.SINGLE_PATTERN)),
        str(TestMessage("net.", "cloudflare.net.", dns.rdatatype.DS, CTC.MULTI_PATTERN, Msg.VALIDATED, Validator.ZSK,
                        CTC.SINGLE_PATTERN)),
        str(TestMessage("cloudflare.net.", "", Types.KSK, CTC.SINGLE_PATTERN, Msg.VALIDATED, Validator.DS,
                        CTC.SINGLE_PATTERN)),
        str(TestMessage("cloudflare.net.", "", dns.rdatatype.DNSKEY, CTC.MULTI_PATTERN, Msg.VALIDATED, Validator.KSK,
                        CTC.SINGLE_PATTERN)),
        str(TestMessage("cloudflare.net.", "www.ietf.org.cdn.cloudflare.net.", dns.rdatatype.A, "", Msg.VALIDATED,
                        Validator.ZSK, CTC.SINGLE_PATTERN)),
        str(TestMessage("cloudflare.net.", "www.ietf.org.cdn.cloudflare.net.", dns.rdatatype.AAAA, "", Msg.VALIDATED,
                        Validator.ZSK, CTC.SINGLE_PATTERN)),
    ]

    WARNIGNS = []

    ERRORS = []

    # fmt: on

    def test_dnssec(self):
        scanner = DNSSECScanner("www.ietf.org")
        result = scanner.run()

        self.maxDiff = None
        self.assert_list(self.LOGS, result.logs)
        self.assert_list(self.WARNIGNS, result.warnings)
        self.assert_list(self.ERRORS, result.errors)

        self.assertEqual(State.SECURE, result.state)


class WwwIetfOrgNonExistence(CTC):
    # fmt: off
    LOGS = [
        str(TestMessage(".", "", Types.KSK, CTC.MULTI_PATTERN, Msg.VALIDATED, Validator.DS, CTC.SINGLE_PATTERN)),
        str(TestMessage(".", "", dns.rdatatype.DNSKEY, CTC.MULTI_PATTERN, Msg.VALIDATED, Validator.KSK,
                        CTC.SINGLE_PATTERN)),
        str(TestMessage(".", "org.", dns.rdatatype.DS, CTC.MULTI_PATTERN, Msg.VALIDATED, Validator.ZSK,
                        CTC.SINGLE_PATTERN)),
        str(TestMessage("org.", "", Types.KSK, CTC.SINGLE_PATTERN, Msg.VALIDATED, Validator.DS, CTC.SINGLE_PATTERN)),
        str(TestMessage("org.", "", dns.rdatatype.DNSKEY, CTC.MULTI_PATTERN, Msg.VALIDATED, Validator.KSK,
                        CTC.SINGLE_PATTERN)),
        str(TestMessage("org.", "", dns.rdatatype.DNSKEY, CTC.MULTI_PATTERN, Msg.VALIDATED, Validator.ZSK,
                        CTC.SINGLE_PATTERN)),
        str(TestMessage("org.", "ietf.org.", dns.rdatatype.DS, CTC.MULTI_PATTERN, Msg.VALIDATED, Validator.ZSK,
                        CTC.SINGLE_PATTERN)),
        str(TestMessage("ietf.org.", "", Types.KSK, CTC.SINGLE_PATTERN, Msg.VALIDATED, Validator.DS,
                        CTC.SINGLE_PATTERN)),
        str(TestMessage("ietf.org.", "", dns.rdatatype.DNSKEY, CTC.MULTI_PATTERN, Msg.VALIDATED, Validator.KSK,
                        CTC.SINGLE_PATTERN)),
        str(TestMessage("ietf.org.", "", dns.rdatatype.DNSKEY, CTC.MULTI_PATTERN, Msg.VALIDATED, Validator.ZSK,
                        CTC.SINGLE_PATTERN)),
        str(TestMessage("ietf.org.", "ietf.org.", dns.rdatatype.SOA, "", Msg.VALIDATED, Validator.ZSK,
                        CTC.SINGLE_PATTERN)),
        str(TestMessage("ietf.org.", "_443._tcp.www.ietf.org.", dns.rdatatype.NSEC, "", Msg.VALIDATED, Validator.ZSK,
                        CTC.SINGLE_PATTERN)),
        str(TestMessage("ietf.org.", "www.ietf.org.", dns.rdatatype.NSEC, "", Msg.VALIDATED, Validator.ZSK,
                        CTC.SINGLE_PATTERN)),
        re.escape("ietf.org. zone: Found closest encloser www.ietf.org."),
        re.escape("ietf.org. zone: Proved that c.www.ietf.org. does not exist"),
        re.escape("ietf.org. zone: Proved that b.c.www.ietf.org. does not exist"),
        re.escape("ietf.org. zone: Proved that a.b.c.www.ietf.org. does not exist"),
        re.escape("ietf.org. zone: Proved that the wildcard *.www.ietf.org. does not exist"),
    ]

    WARNIGNS = []

    ERRORS = []

    # fmt: on

    def test_dnssec(self):
        scanner = DNSSECScanner("a.b.c.www.ietf.org")
        result = scanner.run()

        self.maxDiff = None
        self.assert_list(self.LOGS, result.logs)
        self.assert_list(self.WARNIGNS, result.warnings)
        self.assert_list(self.ERRORS, result.errors)

        self.assertEqual(State.SECURE, result.state)
