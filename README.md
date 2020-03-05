# Description

This DNSSEC scanner aims to provide a detailed description
of the DNSSEC domain validation. It returns error messages
that can help to debug DNSSEC configuration

## Features
1. Returns on of the three states: Secure, Insecure, Bogus
2. Warns about misconfiguration
3. Gives detailed error messages if the domain could not be
validated

# API usage
**Sample code**
```python
from dnssec_scanner import DNSSECScanner, DNSSECScannerResult

scanner = DNSSECScanner("www.dnssec-failed.org")
res = scanner.run_scan() # type: DNSSECScannerResult
print(res)
```

**Output**
```shell script
Domain: www.dnssec-failed.org, DNSSEC: State.BOGUS

╒════╤═════════════════════════════════════════╤══════════════════════════════════════════╤══════════════════════════════════════╕
│    │ Info                                    │ Warnings                                 │ Errors                               │
╞════╪═════════════════════════════════════════╪══════════════════════════════════════════╪══════════════════════════════════════╡
│  0 │ . zone: Found trusted root KSK 0        │ org. zone: Could not validate DNSKEY     │ dnssec-failed.org. zone: Could not   │
│    │                                         │ with RRSIG 1 (verify failure)            │ validate KSK 0 with DS 0             │
├────┼─────────────────────────────────────────┼──────────────────────────────────────────┼──────────────────────────────────────┤
│  1 │ . zones: DNSKEY successfully validated  │ org. zone: Could not validate DNSKEY     │ dnssec-failed.org. zone: Could not   │
│    │ with RRSIG 0                            │ with RRSIG 2 (verify failure)            │ validate KSK 0 with DS 1             │
├────┼─────────────────────────────────────────┼──────────────────────────────────────────┼──────────────────────────────────────┤
│  2 │ . zone: org. DS record successfully     │ org. zones: DNSKEY successfully          │ dnssec-failed.org. zone: Could not   │
│    │ validated with RRSIG 0                  │ validated with RRSIG 0 and untrusted KSK │ validate DNSKEY with RRSIG 0 (verify │
│    │                                         │                                          │ failure)                             │
├────┼─────────────────────────────────────────┼──────────────────────────────────────────┼──────────────────────────────────────┤
│  3 │ org. zone: KSK 0 successfully validated │ org. zones: DNSKEY successfully          │ dnssec-failed.org. zone: Could not   │
│    │ with DS 0                               │ validated with RRSIG 1 and untrusted KSK │ validate DNSKEY with RRSIG 1 (verify │
│    │                                         │                                          │ failure)                             │
├────┼─────────────────────────────────────────┼──────────────────────────────────────────┼──────────────────────────────────────┤
│  4 │ org. zones: DNSKEY successfully         │                                          │                                      │
│    │ validated with RRSIG 0                  │                                          │                                      │
├────┼─────────────────────────────────────────┼──────────────────────────────────────────┼──────────────────────────────────────┤
│  5 │ org. zone: dnssec-failed.org. DS record │                                          │                                      │
│    │ successfully validated with RRSIG 0     │                                          │                                      │
├────┼─────────────────────────────────────────┼──────────────────────────────────────────┼──────────────────────────────────────┤
│  6 │ dnssec-failed.org. zones: DNSKEY        │                                          │                                      │
│    │ successfully validated with RRSIG 1 and │                                          │                                      │
│    │ untrusted KSK                           │                                          │                                      │
├────┼─────────────────────────────────────────┼──────────────────────────────────────────┼──────────────────────────────────────┤
│  7 │ dnssec-failed.org. zone:  A record      │                                          │                                      │
│    │ successfully validated with RRSIG 0     │                                          │                                      │
╘════╧═════════════════════════════════════════╧══════════════════════════════════════════╧══════════════════════════════════════╛
```
