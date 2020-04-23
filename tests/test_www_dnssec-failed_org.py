import logging

import dns.rdatatype
import re

from tests.utils.custom_test_case import CustomTestCase as CTC
from dnssec_scanner import DNSSECScanner, State
from dnssec_scanner.messages import Validator, Msg, Types
from tests.utils.messages_testing import TestMessage

log = logging.getLogger("dnssec_scanner")
log.setLevel(logging.WARNING)


class WwwDnssecFailedOrg(CTC):

    # fmt: off
    LOGS = [
        str(TestMessage(".", "", Types.KSK, CTC.SINGLE_PATTERN, Msg.VALIDATED, Validator.DS, CTC.SINGLE_PATTERN)),
        str(TestMessage(".", "", dns.rdatatype.DNSKEY, CTC.MULTI_PATTERN, Msg.VALIDATED, Validator.KSK,
                        CTC.SINGLE_PATTERN)),
        str(TestMessage(".", "org.", dns.rdatatype.DS, CTC.MULTI_PATTERN, Msg.VALIDATED, Validator.ZSK,
                        CTC.SINGLE_PATTERN)),
        str(TestMessage("org.", "", Types.KSK, CTC.SINGLE_PATTERN, Msg.VALIDATED, Validator.DS, CTC.SINGLE_PATTERN)),
        str(TestMessage("org.", "", dns.rdatatype.DNSKEY, CTC.MULTI_PATTERN, Msg.VALIDATED, Validator.KSK,
                        CTC.SINGLE_PATTERN)),
        str(TestMessage("org.", "", dns.rdatatype.DNSKEY, CTC.MULTI_PATTERN, Msg.VALIDATED, Validator.KSK,
                        CTC.SINGLE_PATTERN)),
        str(TestMessage("org.", "", dns.rdatatype.DNSKEY, CTC.MULTI_PATTERN, Msg.VALIDATED, Validator.ZSK,
                        CTC.SINGLE_PATTERN)),
        str(TestMessage("org.", "dnssec-failed.org.", dns.rdatatype.DS, CTC.MULTI_PATTERN, Msg.VALIDATED, Validator.ZSK,
                        CTC.SINGLE_PATTERN)),
        str(TestMessage("dnssec-failed.org.", "", dns.rdatatype.DNSKEY, CTC.MULTI_PATTERN, Msg.VALIDATED, Validator.ZSK,
                        CTC.SINGLE_PATTERN)),
        str(TestMessage("dnssec-failed.org.", "www.dnssec-failed.org.", dns.rdatatype.A, "", Msg.VALIDATED,
                        Validator.ZSK, CTC.SINGLE_PATTERN)),
        str(TestMessage("dnssec-failed.org.", "www.dnssec-failed.org.", dns.rdatatype.TXT, "", Msg.VALIDATED,
                        Validator.ZSK, CTC.SINGLE_PATTERN)),
        str(TestMessage("dnssec-failed.org.", "www.dnssec-failed.org.", dns.rdatatype.NSEC, "", Msg.VALIDATED,
                        Validator.ZSK, CTC.SINGLE_PATTERN)),
    ]

    WARNIGNS = []

    ERRORS = [
        str(TestMessage("dnssec-failed.org.", "", Types.KSK, CTC.SINGLE_PATTERN, Msg.DS_NOT_FOUND, "", "")),
        re.escape("dnssec-failed.org. zone: Could not validate any KSK"),
        re.escape("dnssec-failed.org. zone: Could not validate DNSKEY with a trusted KSK"),
        str(TestMessage("dnssec-failed.org.", "", dns.rdatatype.DNSKEY, CTC.MULTI_PATTERN, Msg.VALIDATED,
                        Validator.UNTRUSTED_KSK, CTC.SINGLE_PATTERN)),
    ]

    # fmt: on

    def test_dnssec(self):
        scanner = DNSSECScanner("www.dnssec-failed.org")
        result = scanner.run()

        self.assert_list(self.LOGS, result.logs)
        self.assert_list(self.WARNIGNS, result.warnings)
        self.assert_list(self.ERRORS, result.errors)

        self.assertEqual(State.BOGUS, result.state)
