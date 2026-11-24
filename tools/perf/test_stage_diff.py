"""Opt in with python -m unittest discover -s tools/perf -p test_stage_diff.py."""

import copy
import unittest

from stage_diff import compare_rows, read_rows


class StageDiffTests(unittest.TestCase):
    def test_full_row_and_field_mutations(self):
        original = {
            "timestamp_filetime": 133800000000000001,
            "recovery_candidate": False,
            "citation": {"refs": [{"offset": 517, "length": 56}]},
        }
        mutations = [
            {"timestamp_filetime": 133800000000000002},
            {"recovery_candidate": 0},
            {"citation": {"refs": [{"offset": 518, "length": 56}]}},
            {"new_field": None},
        ]
        self.assertTrue(
            compare_rows([original], [dict(reversed(original.items()))], 1)["passed"]
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                result = compare_rows([original], [{**original, **mutation}], 1)
                self.assertFalse(result["passed"])
                self.assertEqual(result["different_rows"], 1)
        missing = copy.deepcopy(original)
        del missing["citation"]["refs"][0]["length"]
        self.assertEqual(
            compare_rows([original], [missing], 1)["examples"][0]["field"],
            "$.citation.refs[0].length",
        )

    def test_order_duplicates_and_manifest_count(self):
        a, b = {"id": 1}, {"id": 2}
        self.assertEqual(compare_rows([a, b], [b, a], 2)["different_rows"], 2)
        self.assertFalse(compare_rows([a], [a, a], 1)["passed"])
        self.assertFalse(compare_rows([a], [a], 2)["passed"])
        self.assertFalse(compare_rows([], [], 1)["passed"])

    def test_malformed_rows_and_lossless_decimal_input(self):
        for value in ('{"a":1,"a":2}', '{"a":NaN}', "[]", "{}", ""):
            with self.subTest(value=value), self.assertRaises(ValueError):
                list(read_rows([value]))
        result = compare_rows(
            read_rows(['{"x":1.000000000000000001}']),
            read_rows(['{"x":1.000000000000000002}']),
            1,
        )
        self.assertFalse(result["passed"])


if __name__ == "__main__":
    unittest.main()
