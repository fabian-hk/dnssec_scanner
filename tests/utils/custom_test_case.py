import unittest
import re


class CustomTestCase(unittest.TestCase):
    # regex pattern for multiple numbers separated by comma
    MULTI_PATTERN = r"[0-9]+(,[0-9]+)*"
    # regex pattern for a single number
    SINGLE_PATTERN = r"[0-9]+"

    def assert_list(self, l1, l2):
        for el2 in l2:
            success = False
            # Search independent from the array order
            # for a match.
            for el1 in l1:
                match = re.match(el1, el2)
                success |= bool(match)
                if success:
                    break

            self.assertTrue(success, f"Could not find a match for: {el2}")
