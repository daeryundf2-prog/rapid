"""Argparse ``choices`` resolved on first use (T-161b).

Some choice lists are derived from engine registries (artifact collectors,
file-category rules, collect profiles). Importing those engines just to build
the parser would make ``rapidtriage --help`` load ``rapidtriage.artifacts`` and
``cv2``/``numpy``. ``set_lazy_choices`` attaches a sequence that calls its
loader the first time argparse reads it: when a value is validated, or when that
subcommand's help/usage is formatted. Help text and validation are unchanged.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable, Iterable, Iterator, Sequence


class LazyChoices(Sequence[str]):
    """Read-only sequence whose items come from ``loader`` on first access."""

    def __init__(self, loader: Callable[[], Iterable[str]]) -> None:
        self._loader = loader
        self._items: tuple[str, ...] | None = None

    def _resolve(self) -> tuple[str, ...]:
        if self._items is None:
            self._items = tuple(self._loader())
        return self._items

    def __getitem__(self, index):  # type: ignore[override]
        return self._resolve()[index]

    def __len__(self) -> int:
        return len(self._resolve())

    def __iter__(self) -> Iterator[str]:
        return iter(self._resolve())

    def __contains__(self, value: object) -> bool:
        return value in self._resolve()

    def __repr__(self) -> str:
        return repr(list(self._resolve()))


def set_lazy_choices(action: argparse.Action, loader: Callable[[], Iterable[str]]) -> argparse.Action:
    """Attach lazily loaded ``choices`` to an action returned by ``add_argument``.

    ``add_argument`` formats the metavar (iterating ``choices``) while it runs,
    so the choices are attached afterwards, not passed to it.
    """
    action.choices = LazyChoices(loader)
    return action


def artifact_kind_choices() -> list[str]:
    from ...core.artifacts import SUPPORTED_ARTIFACT_KINDS

    return sorted(SUPPORTED_ARTIFACT_KINDS)


def file_category_choices() -> list[str]:
    from ...core.files import ALL_FILE_CATEGORIES

    return sorted(ALL_FILE_CATEGORIES)


def collect_profile_choices() -> list[str]:
    from ...core.collect_plan import supported_collect_profiles

    return sorted(supported_collect_profiles())
