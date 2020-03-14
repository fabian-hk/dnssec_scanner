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

scanner = DNSSECScanner("rhybar.cz")
res = scanner.run_scan() # type: DNSSECScannerResult
print(res)
```

**Output**
```shell script
Domain: rhybar.cz, DNSSEC: State.BOGUS

╒════╤══════════════════════════════════════════╤═════════════════════════════════════╤══════════════════════════════════════════╕
│    │ Info                                     │ Warnings                            │ Errors                                   │
╞════╪══════════════════════════════════════════╪═════════════════════════════════════╪══════════════════════════════════════════╡
│  0 │ . zone: KSK 20326 successfully validated │ rhybar.cz. zone: Could not validate │ rhybar.cz. zone: Could not find a DS RR  │
│    │ with trusted DS 20326 8 2                │ DNSKEY with untrusted KSK 44566     │ set for KSK 44566                        │
│    │                                          │ (expired)                           │                                          │
├────┼──────────────────────────────────────────┼─────────────────────────────────────┼──────────────────────────────────────────┤
│  1 │ . zones: DNSKEY successfully validated   │ rhybar.cz. zone: Could not validate │ rhybar.cz. zone: Could not validate any  │
│    │ with trusted KSK 20326                   │ DNSKEY with ZSK 5172 (expired)      │ KSK                                      │
├────┼──────────────────────────────────────────┼─────────────────────────────────────┼──────────────────────────────────────────┤
│  2 │ . zone: cz. DS record successfully       │                                     │ rhybar.cz. zones: Could not validated    │
│    │ validated with ZSK 33853                 │                                     │ DNSKEY with a trusted KSK                │
├────┼──────────────────────────────────────────┼─────────────────────────────────────┼──────────────────────────────────────────┤
│  3 │ cz. zone: KSK 20237 successfully         │                                     │ rhybar.cz. zone: Could not validate NS   │
│    │ validated with trusted DS 20237 13 2     │                                     │ for rhybar.cz. with ZSK 5172 (expired)   │
├────┼──────────────────────────────────────────┼─────────────────────────────────────┼──────────────────────────────────────────┤
│  4 │ cz. zones: DNSKEY successfully validated │                                     │ rhybar.cz. zone: Could not validate SOA  │
│    │ with trusted KSK 20237                   │                                     │ for rhybar.cz. with ZSK 5172 (expired)   │
├────┼──────────────────────────────────────────┼─────────────────────────────────────┼──────────────────────────────────────────┤
│  5 │ cz. zone: DNSKEY successfully validated  │                                     │ rhybar.cz. zone: Could not find RRSIG    │
│    │ with ZSK 16513                           │                                     │ for MX                                   │
├────┼──────────────────────────────────────────┼─────────────────────────────────────┼──────────────────────────────────────────┤
│  6 │ cz. zone: rhybar.cz. DS record           │                                     │ rhybar.cz. zone: Could not validate NSEC │
│    │ successfully validated with ZSK 16513    │                                     │ for rhybar.cz. with ZSK 5172 (expired)   │
├────┼──────────────────────────────────────────┼─────────────────────────────────────┼──────────────────────────────────────────┤
│  7 │                                          │                                     │ rhybar.cz. zone: Could not validate NSEC │
│    │                                          │                                     │ for rhybar.cz. with ZSK 5172 (expired)   │
╘════╧══════════════════════════════════════════╧═════════════════════════════════════╧══════════════════════════════════════════╛
```
