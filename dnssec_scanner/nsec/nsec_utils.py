from __future__ import annotations
from typing import List, Optional, Tuple, Set

import dns
import dns.rdtypes
import hashlib
import base64


def qname_covered_by_nsec(
        nsecs: List[dns.rdtypes.ANY.NSEC], qname: dns.name.Name
) -> bool:
    for name, nsec in nsecs:
        if (
                compare_canonical_order(name, qname) == -1
                and compare_canonical_order(qname, nsec.items[0].next) == -1
        ):
            return True

    return False


def compare_canonical_order(name1: dns.name.Name, name2: dns.name.Name) -> int:
    """
    returns 0 if both are equal
    returns -1 if name1 < name2
    returns 1 if name1 > name2

    :param name1:
    :type name1: dns.name.Name
    :param name2:
    :type name2: dns.name.Name
    """
    lower = bytes.maketrans(
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZ", b"abcdefghijklmnopqrstuvwxyz"
    )

    l = min(len(name1), len(name2))
    d_n1 = len(name1) - l
    d_n2 = len(name2) - l

    for i in range(l - 1, -1, -1):
        n1 = bytes(name1[i + d_n1]).translate(lower)
        n2 = bytes(name2[i + d_n2]).translate(lower)
        if n1 < n2:
            return -1
        elif n1 > n2:
            return 1

    if len(name1) > len(name2):
        return 1
    elif len(name1) < len(name2):
        return -1

    return 0


def nsec3_hash(
        domain: str, salt: Optional[str, bytes], iterations: int, algo: int
) -> str:
    """
    Hash calculation: https://tools.ietf.org/html/rfc5155#section-5

    Domain encoding: https://tools.ietf.org/html/rfc4034#section-6.2
        Use method from dnspython

    Output encoding is base32hex: https://tools.ietf.org/html/rfc4648#section-7
        We need to substitute the characters.

    :param domain:
    :param salt:
    :param iterations:
    :return:
    """
    if algo != 1:
        raise ValueError("Wrong hash algorithm (only SHA1 is supported)")

    b32_to_b32hex = str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", "0123456789ABCDEFGHIJKLMNOPQRSTUV"
    )

    domain_encoded = dns.name.from_text(domain).canonicalize().to_wire()

    salt_encoded = salt
    if isinstance(salt, str):
        if len(salt) % 2 == 0:
            salt_encoded = bytes.fromhex(salt)
        else:
            raise ValueError("Invalid salt length")

    digest = hashlib.sha1(domain_encoded + salt_encoded).digest()
    for i in range(iterations):
        digest = hashlib.sha1(digest + salt_encoded).digest()

    output = base64.b32encode(digest).decode("utf-8")
    output = output.translate(b32_to_b32hex)

    return output


def nsec3_next_to_string(nsec3: dns.rdtypes.ANY.NSEC3):
    b32_to_b32hex = str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", "0123456789ABCDEFGHIJKLMNOPQRSTUV"
    )
    return base64.b32encode(nsec3.next).decode("utf-8").translate(b32_to_b32hex)


def nsec_window_to_array(
        nsec: Optional[dns.rdtypes.ANY.NSEC, dns.rdtypes.ANY.NSEC3]
) -> Set[int]:
    rrset_types = []
    for window, bitmap in nsec.windows:
        for i, b in enumerate(bitmap):
            for j in range(8):
                if b & (0x80 >> j):
                    rrset_types.append(window * 256 + i * 8 + j)
                    # print(f"Type: {dns.rdatatype.to_text(window * 256 + i * 8 + j)}")

    rrset_types = set(rrset_types)
    return rrset_types
