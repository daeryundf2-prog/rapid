"""tests/_timing.py: wall-clock budgets scaled by RAPIDTRIAGE_TEST_TIME_SCALE."""

from __future__ import annotations

import os
import unittest
from unittest import mock

from tests._timing import TIME_SCALE_ENV, time_budget, time_scale


class TimeBudgetTests(unittest.TestCase):
    def _with(self, value: str | None):
        env = {k: v for k, v in os.environ.items() if k != TIME_SCALE_ENV}
        if value is not None:
            env[TIME_SCALE_ENV] = value
        return mock.patch.dict(os.environ, env, clear=True)

    def test_unset_is_one_x(self) -> None:
        with self._with(None):
            self.assertEqual(time_scale(), 1.0)
            self.assertEqual(time_budget(0.5), 0.5)

    def test_set_scales_the_budget(self) -> None:
        with self._with("3"):
            self.assertEqual(time_budget(0.5), 1.5)
        with self._with(" 2.5 "):
            self.assertEqual(time_budget(2.0), 5.0)

    def test_invalid_or_below_one_is_one_x(self) -> None:
        for value in ("", "fast", "nan", "inf", "-inf", "0", "0.5", "-3"):
            with self._with(value):
                self.assertEqual(time_budget(2.0), 2.0, value)

    def test_read_at_call_time(self) -> None:
        with self._with("2"):
            self.assertEqual(time_budget(1.0), 2.0)
        with self._with("4"):
            self.assertEqual(time_budget(1.0), 4.0)


if __name__ == "__main__":
    unittest.main()
