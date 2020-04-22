import logging

import dns.rdatatype
import re

from tests.utils.custom_test_case import CustomTestCase as CTC
from dnssec_scanner import DNSSECScanner, State
from dnssec_scanner.messages import Validator, Msg, Types
from tests.utils.messages_testing import TestMessage

log = logging.getLogger("dnssec_scanner")
log.setLevel(logging.WARNING)


class YesCom(CTC):
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
        str(TestMessage("com.", "yes.com.", dns.rdatatype.DS, CTC.MULTI_PATTERN, Msg.VALIDATED, Validator.ZSK,
                        CTC.SINGLE_PATTERN)),
        str(TestMessage("yes.com.", "", Types.KSK, CTC.SINGLE_PATTERN, Msg.VALIDATED, Validator.DS,
                        CTC.SINGLE_PATTERN)),
        str(TestMessage("yes.com.", "", dns.rdatatype.DNSKEY, CTC.MULTI_PATTERN, Msg.VALIDATED, Validator.KSK,
                        CTC.SINGLE_PATTERN)),
        str(TestMessage("yes.com.", "", dns.rdatatype.DNSKEY, CTC.MULTI_PATTERN, Msg.VALIDATED, Validator.ZSK,
                        CTC.SINGLE_PATTERN)),
        str(TestMessage("yes.com.", "yes.com.", dns.rdatatype.A, "", Msg.VALIDATED, Validator.ZSK, CTC.SINGLE_PATTERN)),
        str(TestMessage("yes.com.", "yes.com.", dns.rdatatype.NS, "", Msg.VALIDATED, Validator.ZSK,
                        CTC.SINGLE_PATTERN)),
        str(TestMessage("yes.com.", "yes.com.", dns.rdatatype.CAA, "", Msg.VALIDATED, Validator.ZSK,
                        CTC.SINGLE_PATTERN)),
        str(TestMessage("yes.com.", "yes.com.", dns.rdatatype.SOA, "", Msg.VALIDATED, Validator.ZSK,
                        CTC.SINGLE_PATTERN)),
        str(TestMessage("yes.com.", "yes.com.", dns.rdatatype.MX, "", Msg.VALIDATED, Validator.ZSK,
                        CTC.SINGLE_PATTERN)),
        str(TestMessage("yes.com.", "yes.com.", dns.rdatatype.TXT, "", Msg.VALIDATED, Validator.ZSK,
                        CTC.SINGLE_PATTERN)),
        str(TestMessage("yes.com.", "yes.com.", dns.rdatatype.NSEC3PARAM, "", Msg.VALIDATED, Validator.ZSK,
                        CTC.SINGLE_PATTERN)),
        str(TestMessage("yes.com.", "yes.com.", "TYPE65534", "", Msg.VALIDATED, Validator.ZSK, CTC.SINGLE_PATTERN)),
    ]

    WARNIGNS = []

    ERRORS = []

    # fmt: on

    def test_dnssec(self):
        scanner = DNSSECScanner("yes.com")
        result = scanner.run()

        self.assert_list(self.LOGS, result.logs)
        self.assert_list(self.WARNIGNS, result.warnings)
        self.assert_list(self.ERRORS, result.errors)

        self.assertEqual(State.SECURE, result.state)


class YesComNonExistence(CTC):
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
        str(TestMessage("com.", "yes.com.", dns.rdatatype.DS, CTC.MULTI_PATTERN, Msg.VALIDATED, Validator.ZSK,
                        CTC.SINGLE_PATTERN)),
        str(TestMessage("yes.com.", "", Types.KSK, CTC.SINGLE_PATTERN, Msg.VALIDATED, Validator.DS,
                        CTC.SINGLE_PATTERN)),
        str(TestMessage("yes.com.", "", dns.rdatatype.DNSKEY, CTC.MULTI_PATTERN, Msg.VALIDATED, Validator.KSK,
                        CTC.SINGLE_PATTERN)),
        str(TestMessage("yes.com.", "", dns.rdatatype.DNSKEY, CTC.MULTI_PATTERN, Msg.VALIDATED, Validator.ZSK,
                        CTC.SINGLE_PATTERN)),
        str(TestMessage("yes.com.", "yes.com.", dns.rdatatype.SOA, "", Msg.VALIDATED, Validator.ZSK,
                        CTC.SINGLE_PATTERN)),
        str(TestMessage("yes.com.", "[a-z0-9]{32}.yes.com.", dns.rdatatype.NSEC3, "", Msg.VALIDATED,
                        Validator.ZSK, CTC.SINGLE_PATTERN)),
        str(TestMessage("yes.com.", "[a-z0-9]{32}.yes.com.", dns.rdatatype.NSEC3, "", Msg.VALIDATED,
                        Validator.ZSK, CTC.SINGLE_PATTERN)),
        str(TestMessage("yes.com.", "[a-z0-9]{32}.yes.com.", dns.rdatatype.NSEC3, "", Msg.VALIDATED,
                        Validator.ZSK, CTC.SINGLE_PATTERN)),
        str(TestMessage("yes.com.", "yes.com.", dns.rdatatype.NSEC3PARAM, "", Msg.VALIDATED, Validator.ZSK,
                        CTC.SINGLE_PATTERN)),
        re.escape("yes.com. zone: Found closest encloser yes.com."),
        re.escape("yes.com. zone: Found NSEC3 that covers the next closer name a.yes.com."),
        re.escape("yes.com. zone: Found NSEC3 that covers the wildcard *.yes.com.")
    ]

    WARNIGNS = []

    ERRORS = []

    # fmt: on

    def test_dnssec(self):
        scanner = DNSSECScanner("a.yes.com")
        result = scanner.run()

        self.assert_list(self.LOGS, result.logs)
        self.assert_list(self.WARNIGNS, result.warnings)
        self.assert_list(self.ERRORS, result.errors)

        self.assertEqual(State.SECURE, result.state)
