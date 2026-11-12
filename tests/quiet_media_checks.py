"""Test helper: keep the optional deepfake_lens engine's per-check tracebacks out of test output.

Runs over the synthetic sample case feed small fake media (``screen-capture.png`` is a PNG
signature and a few bytes). When deepfake_lens is installed, each of its checks logs
``logger.exception("check %s failed")`` for such a file; the package installs no handler, so
Python's last-resort handler prints the full PIL traceback ("Truncated File Read",
UnidentifiedImageError) to stderr -- hundreds of them per full run (T-148). The run's coverage
records still carry the failures; only the console copy is dropped, and only while a test module
that opts in is running (product logging is unchanged).

A module opts in with::

    from tests import quiet_media_checks

    setUpModule = quiet_media_checks.setUpModule
    tearDownModule = quiet_media_checks.tearDownModule
"""

from __future__ import annotations

import logging

NOISY_LOGGERS = ("deepfake_lens",)

_saved: list[tuple[logging.Logger, int]] = []


def silence() -> None:
    """Raise the deepfake_lens loggers to CRITICAL (nested calls stack; :func:`restore` undoes one)."""
    for name in NOISY_LOGGERS:
        logger = logging.getLogger(name)
        _saved.append((logger, logger.level))
        logger.setLevel(logging.CRITICAL)


def restore() -> None:
    for _ in NOISY_LOGGERS:
        if not _saved:
            return
        logger, level = _saved.pop()
        logger.setLevel(level)


def setUpModule() -> None:
    silence()


def tearDownModule() -> None:
    restore()
