import unittest

from random import randint
import dns

from dnssec_scanner.nsec import nsec_utils


class NSEC3Hash(unittest.TestCase):
    DATA = [
        # Source: https://tools.ietf.org/html/rfc5155#appendix-A
        ("example", "aabbccdd", 12, "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom", 1),
        ("a.example", "aabbccdd", 12, "35mthgpgcu1qg68fab165klnsnk3dpvl", 1),
        ("ai.example", "aabbccdd", 12, "gjeqe526plbf1g8mklp59enfd789njgi", 1),
        ("ns1.example", "aabbccdd", 12, "2t7b4g4vsa5smi47k61mv5bv1a22bojr", 1),
        ("ns2.example", "aabbccdd", 12, "q04jkcevqvmu85r014c7dkba38o0ji5r", 1),
        ("w.example", "aabbccdd", 12, "k8udemvp1j2f7eg6jebps17vp3n8i58h", 1),
        ("*.w.example", "aabbccdd", 12, "r53bq7cc2uvmubfu5ocmm6pers9tk9en", 1),
        ("x.w.example", "aabbccdd", 12, "b4um86eghhds6nea196smvmlo4ors995", 1),
        ("y.w.example", "aabbccdd", 12, "ji6neoaepv8b5o6k4ev33abha8ht9fgc", 1),
        ("x.y.w.example", "aabbccdd", 12, "2vptu5timamqttgl4luu9kg21e0aor3s", 1),
        ("xx.example", "aabbccdd", 12, "t644ebqk9bibcna874givr6joj62mlhv", 1),
        (
            "2t7b4g4vsa5smi47k61mv5bv1a22bojr.example",
            "aabbccdd",
            12,
            "kohar7mbb8dc2ce8a9qvl8hon4k53uhi",
            1,
        ),
        # Source: generated with knsec3hash (Linux knot package)
        ("example.com", "9F1AB450CF71D6", 0, "qfo2sv6jaej4cm11a3npoorfrckdao2c", 1),
        ("example.com", "9F1AB450CF71D6", 1, "1nr64to0bb861lku97deb4ubbk6cl5qh", 1),
        ("example.com.", "AF6AB45CCF79D6", 6, "sale3fn6penahh1lq5oqtr5rcl1d113a", 1),
        ("test.domain.dev.", "", 6, "8q98lv9jgkhoq272e42c8blesivia7bu", 1),
        ("www.test.domain.dev.", "B4", 2, "nv7ti6brgh94ke2f3pgiigjevfgpo5j0", 1),
        ("*.test-domain.dev", "", 0, "o6uadafckb6hea9qpcgir2gl71vt23gu", 1),
        ("*.test-domain.dev", "", 45, "505k9g118d9sofnjhh54rr8fadgpa0ct", 1),
    ]

    def test_hash_function(self):
        for d in self.DATA:
            hash = nsec_utils.nsec3_hash(d[0], d[1], d[2], d[4])
            self.assertEqual(hash, d[3].upper(), f"Error {d}")

    def test_hash_invalid_salt_length(self):
        data = (
            "example.com",
            "9F1AB450CF71D",
            0,
            "qfo2sv6jaej4cm11a3npoorfrckdao2c",
            1,
        )
        with self.assertRaises(ValueError):
            hash = nsec_utils.nsec3_hash(data[0], data[1], data[2], data[4])


class NSECCanonicalOrder(unittest.TestCase):
    # Source: https://tools.ietf.org/html/rfc4034#section-6.1
    DATA = (
        dns.name.from_text(b"example"),
        dns.name.from_text(b"a.example"),
        dns.name.from_text(b"yljkjljk.a.example"),
        dns.name.from_text(b"Z.a.example"),
        dns.name.from_text(b"zABC.a.EXAMPLE"),
        dns.name.from_text(b"z.example"),
        dns.name.from_text(b"\001.z.example"),
        dns.name.from_text(b"*.z.example"),
        dns.name.from_text(b"\200.z.example"),
    )

    TEST_ORDER = [
        (0, 1, -1),
        (5, 6, -1),
        (4, 5, -1),
        (1, 1, 0),
        (8, 8, 0),
        (5, 4, 1),
        (8, 3, 1),
        (7, 6, 1),
    ]

    def test_order_function(self):
        for test_order in self.TEST_ORDER:
            order = nsec_utils.compare_canonical_order(
                self.DATA[test_order[0]], self.DATA[test_order[1]]
            )
            self.assertEqual(test_order[2], order, test_order)

    def test_order_function_random(self):
        for _ in range(1000):
            i = randint(0, len(self.DATA) - 1)
            j = randint(0, len(self.DATA) - 1)

            result = (i > j) - (i < j)
            order = nsec_utils.compare_canonical_order(self.DATA[i], self.DATA[j])
            self.assertEqual(result, order, f"{i}, {j}")


if __name__ == "__main__":
    unittest.main()
