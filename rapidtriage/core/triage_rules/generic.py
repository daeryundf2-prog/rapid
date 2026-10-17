"""Cross-family rules (catalogue family ``generic``, U-F8)."""

from __future__ import annotations

import datetime as dt

from .base import (
    FlagContext,
    RowView,
    Rule,
    RuleResult,
    evidence,
    parse_time,
    register,
    select,
)

TIME_KEY_SUFFIXES = ("_at", "_time", "_timestamp", "_date")
TIME_KEYS = frozenset({"timestamp", "time", "date"})
# FILETIME 0 / Unix 0 / DOS 0 (1980-01-01 local) render as these, also shifted by a time zone:
# "no time", not a garbage value.
ZERO_PLACEHOLDERS = ("1601-01-01", "1600-12-31", "1970-01-01", "1969-12-31", "1979-12-31")


def _is_time_key(key: str) -> bool:
    lowered = key.lower()
    return lowered in TIME_KEYS or lowered.endswith(TIME_KEY_SUFFIXES)


@register("generic.timestamp_out_of_range")
class TimestampOutOfRange(Rule):
    """A top-level time field (``*_at``/``*_time``/``*_date``/``timestamp``) before ``min_year`` or after now + ``future_days``."""

    selector = select(collections=("artifacts", "files", "analysis"))

    def prepare(self, ctx: FlagContext) -> None:
        self._min_year = int(self.param("min_year", 1980))
        self._latest = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=float(self.param("future_days", 1)))
        self._excluded = tuple(str(item).lower() for item in self.param("excluded_key_terms", []))

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        found: list[tuple[str, str]] = []
        for key, value in row.details.items():
            if not isinstance(value, str) or len(value) < 10 or not value[:4].isdigit() or not _is_time_key(str(key)):
                continue
            lowered = str(key).lower()
            if any(term in lowered for term in self._excluded):
                continue
            year = int(value[:4])
            if year < self._min_year:
                if value.startswith(ZERO_PLACEHOLDERS) or year == 0:
                    continue
                found.append((str(key), value))
            elif year >= self._latest.year - 1:
                moment = parse_time(value)
                if moment is not None and moment > self._latest:
                    found.append((str(key), value))
            if len(found) >= 3:
                break
        if not found:
            return None
        return RuleResult(
            evidence(field=found[0][0], value=found[0][1], other_fields=[f"{key}={value}" for key, value in found[1:]]),
            note=f"{found[0][0]} 값 {found[0][1]}은(는) {self._min_year}년 이전이거나 현재 이후입니다(파싱/카빙 오류 또는 조작 가능)",
        )
