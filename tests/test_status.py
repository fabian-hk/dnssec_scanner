import unittest
import logging

from dnssec_scanner import DNSSECScanner, State

log = logging.getLogger("dnssec_scanner")
log.setLevel(logging.WARNING)


class DomainStatus(unittest.TestCase):
    DOMAINS = [
        # Secure domain names
        ("yes.com", State.SECURE),
        ("www.ietf.org", State.SECURE),
        ("a.www.ietf.org", State.SECURE),
        ("internetsociety.org", State.SECURE),
        ("dnssec-tools.org", State.SECURE),
        ("a.dnssec-tools.org", State.SECURE),
        ("dnssec-deployment.org", State.SECURE),
        ("a.dnssec-deployment.org", State.SECURE),
        ("cloudflare.com", State.SECURE),
        ("a.cloudflare.com", State.SECURE),
        ("a.com", State.SECURE),
        # Insecure domain names
        ("google.com", State.INSECURE),
        ("amazon.de", State.INSECURE),
        # Bogus domain names
        ("www.dnssec-failed.org", State.BOGUS),
        ("a.www.dnssec-failed.org", State.BOGUS),
        ("www.brokendnssec.net", State.BOGUS),
        ("a.www.brokendnssec.net", State.BOGUS),
        ("rhybar.cz", State.BOGUS),
    ]

    def test_domains(self):
        for name, state in self.DOMAINS:
            scanner = DNSSECScanner(name)
            result = scanner.run()
            self.assertEqual(
                result.state,
                state,
                f"Domain: {name}, State:  {result.state}, Real state: {state}",
            )
            # time.sleep(1)
