import argparse
import validators
import logging

from dnssec_scanner import DNSSECScanner

logging.getLogger("dnssec_scanner").setLevel(logging.ERROR)


def main():
    parser = argparse.ArgumentParser(
        description="DNSSEC validation with detailed error messages for diagnostic."
    )
    parser.add_argument("domain", type=str, help="Domain name you want to validate.")
    args = parser.parse_args()

    domain = args.domain
    if not validators.domain(domain):
        raise ValueError("You have to enter a valid domain name.")

    scanner = DNSSECScanner(domain)
    result = scanner.run_scan()
    print(result)


if __name__ == "__main__":
    main()
