import argparse
import validators
import logging
import dns

from dnssec_scanner import DNSSECScanner

logging.getLogger("dnssec_scanner").setLevel(logging.INFO)


def main():
    parser = argparse.ArgumentParser(
        description="DNSSEC validation with detailed error messages for diagnostic."
    )
    parser.add_argument("domain", type=str, help="Domain name you want to validate.")
    parser.add_argument(
        "type",
        type=str,
        nargs="?",
        help="Query for a specific DNS resource record type (e.g. A, AAAA, MX, SOA)",
    )
    args = parser.parse_args()

    domain = args.domain
    if not validators.domain(domain):
        raise ValueError("You have to enter a valid domain name.")

    type = -1
    if args.type:
        type = dns.rdatatype.from_text(args.type)

    scanner = DNSSECScanner(domain, type)
    result = scanner.run()
    print(result)


if __name__ == "__main__":
    main()
