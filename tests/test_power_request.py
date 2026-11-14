"""R8 T-353: a run keeps the system (not the display) awake and always releases the request."""

from __future__ import annotations

import unittest
from unittest import mock

from rapidtriage.core import jobs, power
from rapidtriage.core.jobs import RunJob, RunJobStore, RunRequest
from rapidtriage.core.power import (
    ES_CONTINUOUS,
    ES_SYSTEM_REQUIRED,
    prevent_system_sleep,
)

ES_DISPLAY_REQUIRED = 0x00000002


class _FakeCtypes:
    """Stand-in for ``ctypes`` exposing ``windll.kernel32.SetThreadExecutionState``."""

    c_uint32 = object()

    def __init__(self, result: int = 0x80000000) -> None:
        self.set_state = mock.Mock(return_value=result)
        self.windll = mock.Mock()
        self.windll.kernel32.SetThreadExecutionState = self.set_state


def _windows(fake: _FakeCtypes):
    return mock.patch.multiple(power, ctypes=fake, sys=mock.Mock(platform="win32"))


class PowerRequestTests(unittest.TestCase):
    def test_windows_sets_system_required_then_clears(self) -> None:
        fake = _FakeCtypes()
        with _windows(fake):
            with prevent_system_sleep() as acquired:
                self.assertTrue(acquired)
                fake.set_state.assert_called_once_with(ES_CONTINUOUS | ES_SYSTEM_REQUIRED)
        self.assertEqual([c.args[0] for c in fake.set_state.call_args_list],
                         [ES_CONTINUOUS | ES_SYSTEM_REQUIRED, ES_CONTINUOUS])
        for call in fake.set_state.call_args_list:
            self.assertFalse(call.args[0] & ES_DISPLAY_REQUIRED, "the display may sleep")

    def test_released_when_the_body_raises(self) -> None:
        fake = _FakeCtypes()
        with _windows(fake):
            with self.assertRaises(RuntimeError):
                with prevent_system_sleep():
                    raise RuntimeError("run failed")
        self.assertEqual(fake.set_state.call_args_list[-1].args[0], ES_CONTINUOUS)
        self.assertEqual(fake.set_state.call_count, 2)

    def test_failed_request_is_not_released(self) -> None:
        fake = _FakeCtypes(result=0)
        with _windows(fake):
            with prevent_system_sleep() as acquired:
                self.assertFalse(acquired)
        self.assertEqual(fake.set_state.call_count, 1)

    def test_non_windows_makes_no_call_and_raises_nothing(self) -> None:
        fake = _FakeCtypes()
        for platform in ("linux", "darwin"):
            with self.subTest(platform=platform):
                with mock.patch.multiple(power, ctypes=fake, sys=mock.Mock(platform=platform)):
                    with prevent_system_sleep() as acquired:
                        self.assertFalse(acquired)
        self.assertEqual(fake.set_state.call_count, 0)

    def test_missing_kernel32_is_a_no_op(self) -> None:
        broken = mock.Mock(spec=[])  # no windll attribute
        with mock.patch.multiple(power, ctypes=broken, sys=mock.Mock(platform="win32")):
            with prevent_system_sleep() as acquired:
                self.assertFalse(acquired)


class JobPowerWiringTests(unittest.TestCase):
    def _execute(self, side_effect) -> tuple[_FakeCtypes, RunJob]:
        fake = _FakeCtypes()
        store = RunJobStore()
        job = RunJob(run_id="p", request=RunRequest(root="unused", mode="hacking", output_dir="unused"))
        store._jobs["p"] = job
        with _windows(fake), mock.patch.object(jobs, "execute_run_request", side_effect=side_effect):
            try:
                store._execute("p")
            except RuntimeError:
                pass
        return fake, job

    def test_completed_run_releases(self) -> None:
        fake, job = self._execute(lambda *a, **k: {"plan": {"outcome": "complete"}})
        self.assertEqual(job.status, "completed")
        self.assertEqual([c.args[0] for c in fake.set_state.call_args_list],
                         [ES_CONTINUOUS | ES_SYSTEM_REQUIRED, ES_CONTINUOUS])

    def test_cancelled_run_releases(self) -> None:
        fake, job = self._execute(lambda *a, **k: {"plan": {"outcome": "cancelled"}})
        self.assertEqual(job.status, "cancelled")
        self.assertEqual(fake.set_state.call_args_list[-1].args[0], ES_CONTINUOUS)

    def test_failed_run_releases(self) -> None:
        fake, job = self._execute(RuntimeError("boom"))
        self.assertEqual(job.status, "failed")
        self.assertEqual([c.args[0] for c in fake.set_state.call_args_list],
                         [ES_CONTINUOUS | ES_SYSTEM_REQUIRED, ES_CONTINUOUS])


if __name__ == "__main__":
    unittest.main()
