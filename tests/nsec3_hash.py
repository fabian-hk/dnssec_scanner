import unittest

from dnssec_scanner import dnssec_validation


class NSEC3Hash(unittest.TestCase):
    # Source: https://tools.ietf.org/html/rfc5155#appendix-A
    DATA = [
        ("example", "aabbccdd", 12, "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom"),
        ("a.example", "aabbccdd", 12, "35mthgpgcu1qg68fab165klnsnk3dpvl"),
        ("ai.example", "aabbccdd", 12, "gjeqe526plbf1g8mklp59enfd789njgi"),
        ("ns1.example", "aabbccdd", 12, "2t7b4g4vsa5smi47k61mv5bv1a22bojr"),
        ("ns2.example", "aabbccdd", 12, "q04jkcevqvmu85r014c7dkba38o0ji5r"),
        ("w.example", "aabbccdd", 12, "k8udemvp1j2f7eg6jebps17vp3n8i58h"),
        ("*.w.example", "aabbccdd", 12, "r53bq7cc2uvmubfu5ocmm6pers9tk9en"),
        ("x.w.example", "aabbccdd", 12, "b4um86eghhds6nea196smvmlo4ors995"),
        ("y.w.example", "aabbccdd", 12, "ji6neoaepv8b5o6k4ev33abha8ht9fgc"),
        ("x.y.w.example", "aabbccdd", 12, "2vptu5timamqttgl4luu9kg21e0aor3s"),
        ("xx.example", "aabbccdd", 12, "t644ebqk9bibcna874givr6joj62mlhv"),
        (
            "2t7b4g4vsa5smi47k61mv5bv1a22bojr.example",
            "aabbccdd",
            12,
            "kohar7mbb8dc2ce8a9qvl8hon4k53uhi",
        ),
    ]

    def test_hash_function(self):
        for d in self.DATA:
            hash = dnssec_validation.nsec3_hash(d[0], d[1], d[2])
            self.assertEqual(hash, d[3].upper(), f"Error {d}")


if __name__ == "__main__":
    unittest.main()
