"""Regex guard of the search page (plan search-2026-10-13 §3.1/§3.4 "정규식").

Python's ``re`` cannot be interrupted, so a hostile pattern on a hostile row
can hold a worker (and the GIL) for minutes. The guard has two layers:

1. **Static analysis on the parse tree** (``re._parser``; never on the
   pattern text). Rejected with 400 "정규식이 너무 복잡합니다(…)":

   * a quantifier with more than ``SMALL_REPEAT_MAX`` repetitions (``*``,
     ``+``, ``{n,}``, ``{n,40}``) whose body contains another variable
     quantifier at any depth (``(a+)+``, ``((a+))+b``, ``((\\w+))+Z``);
   * such a quantifier whose body contains an alternation with overlapping
     branches (same possible first character, or an empty branch:
     ``(a|b|ab)*c``) or a lookaround (``(?=(a+))+b``);
   * a lookaround containing a quantifier;
   * back references and conditional groups;
   * a chain of more than two unbounded quantifiers that can consume the
     same characters (``[a-z]+[a-z]+[a-z]+=``), and two such quantifiers with
     only optional items between them (``\\w+\\w+``, ``\\w+\\s*\\w+``; each pair
     is cubic on a long run). ``\\w+\\s+\\w+`` (a mandatory disjoint
     separator) and ``.*a.*b`` (a mandatory literal) stay allowed.

2. **Bounded matching** (:class:`GuardedRegex`): a row is matched on at most
   ``ROW_MAX_CHARS`` characters, in slices of ``SLICE_CHARS`` characters
   (``SLICE_OVERLAP`` overlap, cut at a line end when one is near), so a
   single ``search`` call is bounded; after each slice the row's own time
   limit (``ROW_SECONDS``) is checked and a row over it is reported as
   unchecked (never silently as a non-match). A match longer than the
   overlap that crosses a slice boundary is not found (documented limit).

:func:`required_literal` derives the FTS prefilter literal from the same
parse tree (``\\x44``, ``\\u…``, ``\\N{…}``, octal, ``{,n}``, ``(?x)``,
classes with ``]`` are all handled by the parser itself).
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field

try:  # Python 3.11+
    from re import _constants as _sre
    from re import _parser as _sre_parse
except ImportError:  # pragma: no cover - Python < 3.11
    import sre_constants as _sre  # type: ignore[no-redef]
    import sre_parse as _sre_parse  # type: ignore[no-redef]

MAX_REGEX_CHARS = 512
SMALL_REPEAT_MAX = 32
ROW_MAX_CHARS = 64 * 1024
SLICE_CHARS = 384
SLICE_OVERLAP = 128
ROW_SECONDS = 0.05
COMPLEX = "정규식이 너무 복잡합니다"

_MAXREPEAT = _sre.MAXREPEAT
_REPEATS = {_sre.MAX_REPEAT, _sre.MIN_REPEAT}
if hasattr(_sre, "POSSESSIVE_REPEAT"):
    _REPEATS.add(_sre.POSSESSIVE_REPEAT)
_ATOMIC = getattr(_sre, "ATOMIC_GROUP", None)
_ASSERTS = {_sre.ASSERT, _sre.ASSERT_NOT}
_CATEGORY_RE = {
    _sre.CATEGORY_DIGIT: re.compile(r"\d"),
    _sre.CATEGORY_NOT_DIGIT: re.compile(r"\D"),
    _sre.CATEGORY_SPACE: re.compile(r"\s"),
    _sre.CATEGORY_NOT_SPACE: re.compile(r"\S"),
    _sre.CATEGORY_WORD: re.compile(r"\w"),
    _sre.CATEGORY_NOT_WORD: re.compile(r"\W"),
    _sre.CATEGORY_LINEBREAK: re.compile(r"\n"),
    _sre.CATEGORY_NOT_LINEBREAK: re.compile(r"[^\n]"),
}
# ASCII letters that Python's Unicode IGNORECASE also matches with a non-ASCII
# letter (U+0130/U+0131, KELVIN SIGN, LONG S): SQLite LIKE would miss those.
_IGNORECASE_UNSAFE_ASCII = frozenset("IiKkSs")
# Representative characters for first-character overlap tests (plus every
# literal and range endpoint of the pattern itself).
_SAMPLE_BASE = (
    [chr(code) for code in range(128)]
    + list("\u0085\u00a0\u00b2\u00e9\u00df\u0130\u0131\u017f\u03a9\u0430\u0663\u1680\u2003\u2028\u212a\u3000\u4e00\uac00\ud7a3\uff10")
)


class RegexRejected(ValueError):
    """Pattern rejected by the static analysis (``reason`` is Korean, for the 400 message)."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


# ---------------------------------------------------------------------------
# character-set predicates (first characters)
# ---------------------------------------------------------------------------

Pred = Callable[[str], bool]


@dataclass
class First:
    """Possible first characters of a sub-pattern and whether it can match empty."""

    preds: list[Pred] = field(default_factory=list)
    nullable: bool = False

    def contains(self, char: str) -> bool:
        return any(pred(char) for pred in self.preds)


def _class_pred(items: list[tuple[object, object]], ignorecase: bool) -> Pred:
    negate = bool(items) and items[0][0] is _sre.NEGATE
    body = items[1:] if negate else items

    def member(char: str) -> bool:
        code = ord(char)
        for op, av in body:
            if op is _sre.LITERAL and code == av:
                return True
            if op is _sre.RANGE and av[0] <= code <= av[1]:  # type: ignore[index]
                return True
            if op is _sre.CATEGORY and _CATEGORY_RE[av].match(char):
                return True
        return False

    def pred(char: str) -> bool:
        variants = {variant for variant in (char, char.lower(), char.upper()) if len(variant) == 1} if ignorecase else {char}
        hit = any(member(variant) for variant in variants)
        return not hit if negate else hit

    return pred


def _literal_pred(code: int, ignorecase: bool, *, negate: bool = False) -> Pred:
    wanted = chr(code)

    def pred(char: str) -> bool:
        if ignorecase:
            hit = char.lower() == wanted.lower() or char.upper() == wanted.upper()
        else:
            hit = char == wanted
        return not hit if negate else hit

    return pred


def _any_pred(dotall: bool) -> Pred:
    return (lambda char: True) if dotall else (lambda char: char != "\n")


class _Analyzer:
    def __init__(self, flags: int) -> None:
        self.ignorecase = bool(flags & re.IGNORECASE)
        self.dotall = bool(flags & re.DOTALL)
        self.samples: set[str] = set(_SAMPLE_BASE)

    # -- samples ---------------------------------------------------------------

    def collect_samples(self, data: Iterable[tuple[object, object]]) -> None:
        for op, av in data:
            if op in (_sre.LITERAL, _sre.NOT_LITERAL):
                self._add_code(int(av))  # type: ignore[arg-type]
            elif op is _sre.IN:
                for item_op, item_av in av:  # type: ignore[union-attr]
                    if item_op is _sre.LITERAL:
                        self._add_code(int(item_av))
                    elif item_op is _sre.RANGE:
                        low, high = item_av
                        for code in (low - 1, low, high, high + 1):
                            self._add_code(code)
            for child in self._children(op, av):
                self.collect_samples(child)

    def _add_code(self, code: int) -> None:
        if 0 <= code <= 0x10FFFF:
            char = chr(code)
            self.samples.update({char, char.lower()[:1] or char, char.upper()[:1] or char})

    @staticmethod
    def _children(op: object, av: object) -> list[list[tuple[object, object]]]:
        if op in _REPEATS:
            return [list(av[2])]  # type: ignore[index]
        if op is _sre.SUBPATTERN:
            return [list(av[3])]  # type: ignore[index]
        if op is _sre.BRANCH:
            return [list(item) for item in av[1]]  # type: ignore[index]
        if op in _ASSERTS:
            return [list(av[1])]  # type: ignore[index]
        if _ATOMIC is not None and op is _ATOMIC:
            return [list(av)]  # type: ignore[arg-type]
        if op is _sre.GROUPREF_EXISTS:
            return [list(item) for item in av[1:] if item is not None]  # type: ignore[index]
        return []

    def overlap(self, left: First, right: First) -> bool:
        return any(left.contains(char) and right.contains(char) for char in self.samples)

    # -- first sets --------------------------------------------------------------

    def first_of_item(self, op: object, av: object) -> First:
        if op is _sre.LITERAL:
            return First([_literal_pred(int(av), self.ignorecase)])  # type: ignore[arg-type]
        if op is _sre.NOT_LITERAL:
            return First([_literal_pred(int(av), self.ignorecase, negate=True)])  # type: ignore[arg-type]
        if op is _sre.ANY:
            return First([_any_pred(self.dotall)])
        if op is _sre.IN:
            return First([_class_pred(list(av), self.ignorecase)])  # type: ignore[arg-type]
        if op in _REPEATS:
            low = int(av[0])  # type: ignore[index]
            inner = self.first_of_seq(av[2])  # type: ignore[index]
            return First(inner.preds, inner.nullable or low == 0)
        if op is _sre.SUBPATTERN:
            return self.first_of_seq(av[3])  # type: ignore[index]
        if _ATOMIC is not None and op is _ATOMIC:
            return self.first_of_seq(av)  # type: ignore[arg-type]
        if op is _sre.BRANCH:
            merged = First()
            for item in av[1]:  # type: ignore[index]
                part = self.first_of_seq(item)
                merged.preds.extend(part.preds)
                merged.nullable = merged.nullable or part.nullable
            return merged
        if op in (_sre.AT,) or op in _ASSERTS:
            return First([], True)
        return First([lambda char: True], True)  # unknown: anything

    def first_of_seq(self, data: Iterable[tuple[object, object]]) -> First:
        merged = First()
        for op, av in data:
            part = self.first_of_item(op, av)
            merged.preds.extend(part.preds)
            if not part.nullable:
                return merged
        merged.nullable = True
        return merged

    # -- rules -------------------------------------------------------------------

    def check(self, data: list[tuple[object, object]], *, in_large_repeat: bool = False, in_assert: bool = False) -> None:
        for op, av in data:
            if op in (_sre.GROUPREF, _sre.GROUPREF_EXISTS) or op is getattr(_sre, "GROUPREF_IGNORE", None):
                raise RegexRejected(f"{COMPLEX}(역참조·조건 그룹은 쓸 수 없습니다)")
            if op in _REPEATS:
                low, high, body = av  # type: ignore[misc]
                variable = high != low
                large = high == _MAXREPEAT or int(high) > SMALL_REPEAT_MAX
                if in_large_repeat and variable and int(high) > 1:
                    raise RegexRejected(f"{COMPLEX}(반복 안에 다시 반복이 있습니다)")
                if in_assert and int(high) > 1:
                    raise RegexRejected(f"{COMPLEX}(전후방 탐색 안에 반복이 있습니다)")
                if large:
                    self._check_repeat_body(list(body))
                self.check(list(body), in_large_repeat=in_large_repeat or large, in_assert=in_assert)
                continue
            if op in _ASSERTS:
                if in_large_repeat:
                    raise RegexRejected(f"{COMPLEX}(반복 안에 전후방 탐색이 있습니다)")
                self.check(list(av[1]), in_large_repeat=in_large_repeat, in_assert=True)  # type: ignore[index]
                continue
            if op is _sre.BRANCH:
                for item in av[1]:  # type: ignore[index]
                    self.check(list(item), in_large_repeat=in_large_repeat, in_assert=in_assert)
                    self.check_chains(list(item))
                continue
            for child in self._children(op, av):
                self.check(child, in_large_repeat=in_large_repeat, in_assert=in_assert)

    def _check_repeat_body(self, body: list[tuple[object, object]]) -> None:
        """Alternations inside a large repeat must not overlap (``(a|b|ab)*``)."""
        for op, av in body:
            if op is _sre.BRANCH:
                firsts = [self.first_of_seq(item) for item in av[1]]  # type: ignore[index]
                if any(item.nullable for item in firsts):
                    raise RegexRejected(f"{COMPLEX}(반복 안의 선택지가 빈 문자열과 일치합니다)")
                for index, left in enumerate(firsts):
                    for right in firsts[index + 1 :]:
                        if self.overlap(left, right):
                            raise RegexRejected(f"{COMPLEX}(반복 안의 선택지들이 같은 글자로 시작할 수 있습니다)")
            for child in self._children(op, av):
                self._check_repeat_body(child)

    def _flatten(self, data: Iterable[tuple[object, object]]) -> Iterator[tuple[object, object]]:
        """Items of a sequence with plain (non-repeated) groups inlined."""
        for op, av in data:
            if op is _sre.SUBPATTERN:
                yield from self._flatten(av[3])  # type: ignore[index]
            elif _ATOMIC is not None and op is _ATOMIC:
                yield from self._flatten(av)  # type: ignore[arg-type]
            else:
                yield op, av

    def check_chains(self, data: list[tuple[object, object]]) -> None:
        """Unbounded quantifiers competing for the same characters (polynomial backtracking)."""
        # open: (first set of an unbounded repeat, chain length, mandatory item seen since)
        open_: list[list[object]] = []
        for op, av in self._flatten(data):
            if op in _REPEATS:
                low, high, body = av  # type: ignore[misc]
                self.check_chains(list(body))
                if high == _MAXREPEAT or int(high) > SMALL_REPEAT_MAX:
                    current = self.first_of_seq(body)
                    chain = 1
                    for other, length, separated in open_:
                        if self.overlap(other, current):  # type: ignore[arg-type]
                            if not separated:
                                raise RegexRejected(f"{COMPLEX}(같은 글자를 나눠 가질 수 있는 반복이 연달아 있습니다)")
                            chain = max(chain, int(length) + 1)  # type: ignore[call-overload]
                    if chain > 2:
                        raise RegexRejected(f"{COMPLEX}(같은 글자를 나눠 가질 수 있는 반복이 세 개 이상 이어집니다)")
                    if int(low) >= 1:
                        open_ = self._close(open_, current)
                    open_.append([current, chain, False])
                    continue
                if low == 0:
                    continue  # optional bounded item: chains continue through it
                item_first = self.first_of_seq(body)
            elif op is _sre.BRANCH:
                for item in av[1]:  # type: ignore[index]
                    self.check_chains(list(item))
                item_first = self.first_of_item(op, av)
                if item_first.nullable:
                    continue
            else:
                item_first = self.first_of_item(op, av)
                if item_first.nullable:
                    continue
            open_ = self._close(open_, item_first)

    def _close(self, open_: list[list[object]], item_first: First) -> list[list[object]]:
        """A mandatory item: repeats that cannot consume it end here; the others continue past it."""
        kept = []
        for entry in open_:
            if self.overlap(entry[0], item_first):  # type: ignore[arg-type]
                entry[2] = True
                kept.append(entry)
        return kept


@dataclass
class RegexInfo:
    compiled: re.Pattern[str]
    flags: int
    literal: str


def _parse(pattern: str, flags: int) -> tuple[list[tuple[object, object]], int]:
    parsed = _sre_parse.parse(pattern, flags)
    return list(parsed.data), int(parsed.state.flags)


def analyze_regex(pattern: str, ignorecase: bool = False) -> RegexInfo:
    """Compile and statically check ``pattern``; :class:`RegexRejected` / ``re.error`` when unusable."""
    if len(pattern) > MAX_REGEX_CHARS:
        raise RegexRejected(f"정규식이 너무 깁니다(최대 {MAX_REGEX_CHARS}자)")
    flags = re.IGNORECASE if ignorecase else 0
    compiled = re.compile(pattern, flags)
    data, effective = _parse(pattern, flags)
    analyzer = _Analyzer(effective)
    analyzer.collect_samples(data)
    analyzer.check(data)
    analyzer.check_chains(data)
    return RegexInfo(compiled=compiled, flags=effective, literal=_literal_from_tree(data, effective))


# ---------------------------------------------------------------------------
# required literal (FTS prefilter)
# ---------------------------------------------------------------------------


def _usable_char(char: str, ignorecase: bool) -> bool:
    if char in "\x00\n\r":
        return False
    if not ignorecase:
        return True
    if char.isascii():
        return char not in _IGNORECASE_UNSAFE_ASCII
    return char.lower() == char == char.upper()


def _literal_from_tree(data: list[tuple[object, object]], flags: int) -> str:
    if flags & getattr(re, "LOCALE", 0):
        return ""
    ignorecase = bool(flags & re.IGNORECASE)
    best = ""
    run: list[str] = []

    def flush() -> None:
        nonlocal best
        candidate = "".join(run)
        if len(candidate) > len(best):
            best = candidate
        run.clear()

    def walk(items: Iterable[tuple[object, object]]) -> None:
        nonlocal best
        for op, av in items:
            if op is _sre.LITERAL:
                char = chr(int(av))  # type: ignore[arg-type]
                if _usable_char(char, ignorecase):
                    run.append(char)
                else:
                    flush()
            elif op is _sre.SUBPATTERN and not av[1] and not av[2]:  # type: ignore[index]
                walk(av[3])  # type: ignore[index]
            elif op in _REPEATS and int(av[0]) >= 1:  # type: ignore[index]
                flush()
                inner = _literal_from_tree(list(av[2]), flags)  # type: ignore[index]
                if len(inner) > len(best):
                    best = inner
            else:
                flush()

    walk(data)
    flush()
    return best


def required_literal(pattern: str, flags: str = "") -> str:
    """Longest literal every match of ``pattern`` must contain (``""`` when unknown or unparsable)."""
    try:
        data, effective = _parse(pattern, re.IGNORECASE if "i" in flags else 0)
    except (re.error, RecursionError, OverflowError):
        return ""
    return _literal_from_tree(data, effective)


# ---------------------------------------------------------------------------
# bounded matching
# ---------------------------------------------------------------------------


def _slices(length: int, text: str) -> Iterator[tuple[int, int]]:
    if length <= SLICE_CHARS:
        yield 0, length
        return
    start = 0
    while start < length:
        end = min(length, start + SLICE_CHARS)
        if end < length:
            cut = text.rfind("\n", start + SLICE_CHARS - SLICE_OVERLAP, end)
            if cut > start:
                end = cut + 1
        yield start, end
        if end >= length:
            return
        start = max(start + 1, end - SLICE_OVERLAP)


class RowTimeout(Exception):
    """A row exceeded ``ROW_SECONDS`` (between slices); the caller reports it, never as a non-match."""


class GuardedRegex:
    """``search``/``finditer`` on bounded slices with a per-row time limit."""

    def __init__(self, compiled: re.Pattern[str], *, row_seconds: float = ROW_SECONDS) -> None:
        self.compiled = compiled
        self.pattern = compiled.pattern
        self.row_seconds = row_seconds

    def search(self, text: str) -> tuple[int, int] | None:
        """First match span or ``None``; :class:`RowTimeout` when the row is over its time limit."""
        text = text[:ROW_MAX_CHARS]
        deadline = time.monotonic() + self.row_seconds
        for start, end in _slices(len(text), text):
            found = self.compiled.search(text[start:end])
            if found is not None:
                return start + found.start(), start + found.end()
            if time.monotonic() > deadline:
                raise RowTimeout()
        return None

    def spans(self, text: str, limit: int) -> list[tuple[int, int]]:
        """Non-empty match spans in a short ``text`` (snippet windows; at most one slice)."""
        out: list[tuple[int, int]] = []
        for found in self.compiled.finditer(text[:SLICE_CHARS]):
            if found.end() > found.start():
                out.append((found.start(), found.end()))
                if len(out) >= limit:
                    break
        return out
