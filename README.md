# Description

This DNSSEC scanner aims to provide a detailed description
of the DNSSEC domain validation. It returns error messages
that can help to debug DNSSEC configuration.

## Features
1. Returns one of the three states: Secure, Insecure, Bogus
2. Warns about misconfiguration
3. Gives detailed error messages if the domain could not be
validated

## Mechanics
- Starts at a root zone server and searches for an SOA record
- Validates the root zone KSKs with the DS record from 
[iana.org](https://data.iana.org/root-anchors/root-anchors.xml)
- Validates successive all KSKs, ZSKs and DS records from top to bottom
- If there is no DS record it tries to proof it with NSEC or NSEC3
- If the domain does not exist it also tries to proof it with NSEC 
or NSEC3
- If an SOA record is found it tries to find with a list and with a
"ANY" DNS query as many records as possible
- Then it tries to validate those records
- Return comprehensive logs, warnings and error messages in the
DNSSECScannerResult object
- The DNSSECScannerResult object also contains the status and all
found records divided into secure and insecure records

# Usage
## API usage
**Sample code**
```python
from dnssec_scanner import DNSSECScanner, DNSSECScannerResult

scanner = DNSSECScanner("www.ietf.org")
res = scanner.run_scan() # type: DNSSECScannerResult
print(res)
```

## Command-line interface usage
```shell script
$ dnssec-scanner www.ietf.org
```

## Output
```shell script
╒════╤════════════════════════════════════════════════════════════════════════════════════╕
│    │ Logs                                                                               │
╞════╪════════════════════════════════════════════════════════════════════════════════════╡
│  0 │ . zone: KSK 20326 successfully validated with trusted DS 20326 8 2                 │
├────┼────────────────────────────────────────────────────────────────────────────────────┤
│  1 │ . zones: DNSKEY successfully validated with trusted KSK 20326                      │
├────┼────────────────────────────────────────────────────────────────────────────────────┤
│  2 │ . zone: org. DS record successfully validated with ZSK 33853                       │
├────┼────────────────────────────────────────────────────────────────────────────────────┤
│  3 │ org. zone: KSK 9795 successfully validated with trusted DS 9795 7 1                │
├────┼────────────────────────────────────────────────────────────────────────────────────┤
│  4 │ org. zone: KSK 9795 successfully validated with trusted DS 9795 7 2                │
├────┼────────────────────────────────────────────────────────────────────────────────────┤
│  5 │ org. zones: DNSKEY successfully validated with trusted KSK 9795                    │
├────┼────────────────────────────────────────────────────────────────────────────────────┤
│  6 │ org. zone: DNSKEY successfully validated with trusted KSK 17883                    │
├────┼────────────────────────────────────────────────────────────────────────────────────┤
│  7 │ org. zone: DNSKEY successfully validated with ZSK 33209                            │
├────┼────────────────────────────────────────────────────────────────────────────────────┤
│  8 │ org. zone: ietf.org. DS record successfully validated with ZSK 33209               │
├────┼────────────────────────────────────────────────────────────────────────────────────┤
│  9 │ ietf.org. zone: KSK 45586 successfully validated with trusted DS 45586 5 1         │
├────┼────────────────────────────────────────────────────────────────────────────────────┤
│ 10 │ ietf.org. zone: KSK 45586 successfully validated with trusted DS 45586 5 2         │
├────┼────────────────────────────────────────────────────────────────────────────────────┤
│ 11 │ ietf.org. zones: DNSKEY successfully validated with trusted KSK 45586              │
├────┼────────────────────────────────────────────────────────────────────────────────────┤
│ 12 │ ietf.org. zone: DNSKEY successfully validated with ZSK 40452                       │
├────┼────────────────────────────────────────────────────────────────────────────────────┤
│ 13 │ ietf.org. zone: www.ietf.org. CNAME record successfully validated with ZSK 40452   │
├────┼────────────────────────────────────────────────────────────────────────────────────┤
│ 14 │ . zone: net. DS record successfully validated with ZSK 33853                       │
├────┼────────────────────────────────────────────────────────────────────────────────────┤
│ 15 │ net. zone: KSK 35886 successfully validated with trusted DS 35886 8 2              │
├────┼────────────────────────────────────────────────────────────────────────────────────┤
│ 16 │ net. zones: DNSKEY successfully validated with trusted KSK 35886                   │
├────┼────────────────────────────────────────────────────────────────────────────────────┤
│ 17 │ net. zone: cloudflare.net. DS record successfully validated with ZSK 24512         │
├────┼────────────────────────────────────────────────────────────────────────────────────┤
│ 18 │ cloudflare.net. zone: KSK 2371 successfully validated with trusted DS 2371 13 2    │
├────┼────────────────────────────────────────────────────────────────────────────────────┤
│ 19 │ cloudflare.net. zones: DNSKEY successfully validated with trusted KSK 2371         │
├────┼────────────────────────────────────────────────────────────────────────────────────┤
│ 20 │ cloudflare.net. zone: www.ietf.org.cdn.cloudflare.net. A record successfully       │
│    │ validated with ZSK 34505                                                           │
├────┼────────────────────────────────────────────────────────────────────────────────────┤
│ 21 │ cloudflare.net. zone: www.ietf.org.cdn.cloudflare.net. AAAA record successfully    │
│    │ validated with ZSK 34505                                                           │
╘════╧════════════════════════════════════════════════════════════════════════════════════╛
╒════╤════════════════════════════════════════════════════════════════════════════════════╕
│    │ Warnings                                                                           │
╞════╪════════════════════════════════════════════════════════════════════════════════════╡
│  0 │ All good ;)                                                                        │
╘════╧════════════════════════════════════════════════════════════════════════════════════╛
╒════╤════════════════════════════════════════════════════════════════════════════════════╕
│    │ Errors                                                                             │
╞════╪════════════════════════════════════════════════════════════════════════════════════╡
│  0 │ All good ;)                                                                        │
╘════╧════════════════════════════════════════════════════════════════════════════════════╛

Domain: www.ietf.org, DNSSEC: State.SECURE, Note: Found RR sets: A (s), AAAA (s)
```
