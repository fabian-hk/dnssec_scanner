import logging

import dns.rdatatype

from tests.utils.custom_test_case import CustomTestCase as CTC
from dnssec_scanner import DNSSECScanner, State
from dnssec_scanner.messages import Validator, Msg, Types
from tests.utils.messages_testing import TestMessage

log = logging.getLogger("dnssec_scanner")
log.setLevel(logging.WARNING)


class WwwBrokendnssecNet(CTC):
    """
    Last checked on 11.04.2020
    """

    # fmt: off
    LOGS = [
        str(TestMessage(".", "", Types.KSK, CTC.SINGLE_PATTERN, Msg.VALIDATED, Validator.DS, CTC.SINGLE_PATTERN)),
        str(TestMessage(".", "", dns.rdatatype.DNSKEY, CTC.MULTI_PATTERN, Msg.VALIDATED, Validator.KSK,
                        CTC.SINGLE_PATTERN)),
        str(TestMessage(".", "net.", dns.rdatatype.DS, CTC.MULTI_PATTERN, Msg.VALIDATED, Validator.ZSK,
                        CTC.SINGLE_PATTERN)),
        str(TestMessage("net.", "", Types.KSK, CTC.SINGLE_PATTERN, Msg.VALIDATED, Validator.DS, CTC.SINGLE_PATTERN)),
        str(TestMessage("net.", "", dns.rdatatype.DNSKEY, CTC.MULTI_PATTERN, Msg.VALIDATED, Validator.KSK,
                        CTC.SINGLE_PATTERN)),
        str(TestMessage("net.", "brokendnssec.net.", dns.rdatatype.DS, CTC.MULTI_PATTERN, Msg.VALIDATED, Validator.ZSK,
                        CTC.SINGLE_PATTERN)),
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
        result = scanner.run()

        self.assert_list(self.LOGS, result.logs)
        self.assert_list(self.WARNIGNS, result.warnings)
        self.assert_list(self.ERRORS, result.errors)

        self.assertEqual(State.BOGUS, result.state)
