"""Query grammar of the search page (plan §3.1). The server is its only interpreter.

```
query   := or_expr
or_expr := and_expr ("OR" and_expr)*
and_expr:= unary (["AND"] unary)*          (whitespace = AND)
unary   := ("NOT" | "-") unary | atom
atom    := "(" query ")" | field ":" value | value      (a value without a field = kw)
value   := "phrase" | /regex/i? | [a .. b] | (v1, v2, ...) | token
```

A regex is ``re:/…/i?`` (or ``re:<pattern>``); a bare ``/…/`` is a regex only
when it has no whitespace, no inner unescaped ``/`` and ends at a boundary
(``/usr/bin/ls`` is a keyword). Parentheses and ``NOT``/``-`` nest at most
``MAX_DEPTH`` deep.

``AND`` binds tighter than ``OR``. ``field:`` is only a field when ``field``
is a known field name (or ``data.<name>``): ``C:\\Users`` stays a keyword.
Errors are :class:`QueryError` with a 1-based character ``position`` and a
Korean message (``질의 7번째 글자: 닫는 괄호가 없습니다``).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .regex_guard import (
    MAX_REGEX_CHARS,
    RegexInfo,
    RegexRejected,
    analyze_regex,
    required_literal,
)
from .textutil import is_bigram_term, nfc

# Short keywords the indexes cannot serve (R7 S2): 3+ characters use the trigram index,
# 2 non-ASCII characters the bigram table (index v3); the rest scan every row's text.
SHORT_ONE_WARNING = "1자 검색어는 색인을 쓰지 못해 전체 본문을 훑습니다(느릴 수 있음)"
SHORT_TWO_WARNING = "영문·숫자·기호가 든 2자 검색어는 색인을 쓰지 못해 전체 본문을 훑습니다(느릴 수 있음)"

MAX_QUERY_CHARS = 4000
MAX_CLAUSES = 64
MAX_LIST_ITEMS = 256
MAX_DEPTH = 32
LOWERCASE_OPERATORS = frozenset({"or", "and", "not"})

__all__ = ["MAX_REGEX_CHARS", "QueryError", "parse_query", "required_literal", "validate_regex"]

# Fields implemented in S1 (and the cheap S2 event fields).
S1_FIELDS = frozenset(
    {
        "kw", "word", "re", "near",
        "time", "around", "tskind", "in", "type", "actor", "sid", "computer", "afterhours", "gap",
        "hash", "md5", "sha1", "sha256", "hashset",
        "path", "ext", "extset", "size", "deleted", "mismatch", "archive", "under", "author", "savedby", "template",
        "review", "tag", "note", "bookmark", "analysis",
        "eventid", "provider", "channel",
    }
)
S2_FIELDS = frozenset(
    {"list", "ip", "host", "url", "email", "iocset", "user", "logon", "phone", "rrn", "card", "account", "regkey", "regval", "regdata", "regtype"}
)
S3_FIELDS = frozenset({"geo", "camera", "taken", "phash", "similar"})
KNOWN_FIELDS = S1_FIELDS | S2_FIELDS | S3_FIELDS
TEXT_FIELDS = frozenset({"kw", "word", "re", "near"})
BOOL_FIELDS = frozenset({"afterhours", "deleted", "mismatch", "archive", "bookmark"})
# Fields whose value is a directive for the result (not a row filter that NOT/OR could invert).
DIRECTIVE_FIELDS = frozenset({"gap"})

CHIPS = {
    "kw": "keyword", "word": "keyword", "re": "keyword", "near": "keyword",
    "time": "time", "around": "time", "tskind": "time", "afterhours": "time", "gap": "time",
    "in": "scope", "type": "scope", "analysis": "scope",
    "actor": "identity", "sid": "identity", "computer": "identity",
    "hash": "hash", "md5": "hash", "sha1": "hash", "sha256": "hash", "hashset": "hash",
    "path": "path", "ext": "path", "extset": "path", "size": "path", "deleted": "path", "mismatch": "path",
    "archive": "path", "under": "path", "author": "path", "savedby": "path", "template": "path",
    "review": "review", "tag": "review", "note": "review", "bookmark": "review",
    "eventid": "event", "provider": "event", "channel": "event",
}
FIELD_LABELS = {
    "kw": "키워드", "word": "단어", "re": "정규식", "near": "근접", "time": "시간", "around": "전후", "tskind": "시각 종류",
    "in": "도메인", "type": "유형", "actor": "행위자", "sid": "SID", "computer": "컴퓨터", "afterhours": "업무 시간 외",
    "gap": "빈 구간", "hash": "해시", "md5": "MD5", "sha1": "SHA-1", "sha256": "SHA-256", "hashset": "해시 세트",
    "path": "경로", "ext": "확장자", "extset": "확장자 묶음", "size": "크기", "deleted": "삭제됨", "mismatch": "시그니처 불일치",
    "archive": "압축 내부", "under": "폴더 아래", "author": "작성자", "savedby": "마지막 저장자", "template": "템플릿",
    "review": "리뷰 상태", "tag": "태그", "note": "메모", "bookmark": "북마크", "analysis": "분석",
    "eventid": "이벤트 ID", "provider": "제공자", "channel": "채널",
}

_FIELD_NAME_RE = re.compile(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_][A-Za-z0-9_.-]*)?")
_OPERATORS = {"AND", "OR", "NOT"}


class QueryError(ValueError):
    """A query the grammar rejects: Korean ``message`` and 1-based ``position`` (0 = whole query)."""

    def __init__(self, message: str, position: int = 0, *, status: int = 400) -> None:
        self.message = message
        self.position = position
        self.status = status
        super().__init__(self.detail)

    @property
    def detail(self) -> str:
        if self.position > 0:
            return f"질의 {self.position}번째 글자: {self.message}"
        return self.message


@dataclass
class Value:
    kind: str  # token | phrase | regex | range | list
    text: str = ""
    flags: str = ""
    low: str = ""
    high: str = ""
    items: list[Value] = field(default_factory=list)
    pos: int = 0

    def display(self) -> str:
        if self.kind == "phrase":
            return '"' + self.text.replace('"', '\\"') + '"'
        if self.kind == "regex":
            return f"/{self.text}/{self.flags}"
        if self.kind == "range":
            return f"[{self.low} .. {self.high}]"
        if self.kind == "list":
            return "(" + ", ".join(item.display() for item in self.items) + ")"
        return self.text


@dataclass
class Term:
    field: str
    value: Value
    pos: int
    raw: str

    def display(self) -> str:
        return f"{self.field}:{self.value.display()}"


@dataclass
class Not:
    child: Node
    pos: int


@dataclass
class Group:
    op: str  # AND | OR
    children: list[Node]
    pos: int


Node = Term | Not | Group


@dataclass
class ParsedQuery:
    raw: str
    root: Node | None
    terms: list[tuple[Term, bool]]  # (term, negated)
    warnings: list[str]

    def clauses(self) -> list[dict[str, object]]:
        return [
            {
                "field": term.field,
                "op": op_of(term),
                "value": value_payload(term.value),
                "negated": negated,
                "chip": CHIPS.get(term.field, "event" if term.field.startswith("data.") else "keyword"),
                "display": ("-" if negated else "") + term.display(),
                "label": FIELD_LABELS.get(term.field, term.field),
                "position": term.pos,
            }
            for term, negated in self.terms
        ]


def op_of(term: Term) -> str:
    if term.field == "re" or term.value.kind == "regex":
        return "regex"
    if term.value.kind == "range":
        return "range"
    if term.value.kind == "list":
        return "in"
    if term.field in TEXT_FIELDS:
        return "contains" if term.field == "kw" else term.field
    return "eq"


def value_payload(value: Value) -> object:
    if value.kind == "range":
        return {"from": value.low, "to": value.high}
    if value.kind == "list":
        return [value_payload(item) for item in value.items]
    if value.kind == "regex":
        return {"pattern": value.text, "flags": value.flags}
    return value.text


# ---------------------------------------------------------------------------
# tokenizer / parser
# ---------------------------------------------------------------------------


class _Parser:
    def __init__(self, text: str) -> None:
        self.text = text
        self.i = 0
        self.clauses = 0
        self.depth = 0

    def enter(self, start: int) -> None:
        self.depth += 1
        if self.depth > MAX_DEPTH:
            raise self.error(f"괄호·NOT이 너무 깊게 겹쳐 있습니다(최대 {MAX_DEPTH}단계)", start)

    # -- helpers -------------------------------------------------------------

    def error(self, message: str, index: int | None = None) -> QueryError:
        return QueryError(message, (self.i if index is None else index) + 1)

    def skip_ws(self) -> None:
        while self.i < len(self.text) and self.text[self.i].isspace():
            self.i += 1

    def at_end(self) -> bool:
        self.skip_ws()
        return self.i >= len(self.text)

    def peek_operator(self) -> str | None:
        self.skip_ws()
        for op in _OPERATORS:
            end = self.i + len(op)
            if self.text.startswith(op, self.i) and (end >= len(self.text) or self.text[end].isspace() or self.text[end] == "("):
                return op
        return None

    # -- grammar -------------------------------------------------------------

    def parse(self) -> Node | None:
        if self.at_end():
            return None
        node = self.parse_or()
        self.skip_ws()
        if self.i < len(self.text):
            if self.text[self.i] == ")":
                raise self.error("여는 괄호 없이 닫는 괄호가 있습니다")
            raise self.error("질의를 해석할 수 없습니다")
        return node

    def parse_or(self) -> Node:
        start = self.i
        children = [self.parse_and()]
        while self.peek_operator() == "OR":
            op_pos = self.i
            self.i += 2
            if self.at_end() or self.text[self.i] == ")":
                raise self.error("OR 뒤에 조건이 없습니다", op_pos)
            children.append(self.parse_and())
        return children[0] if len(children) == 1 else Group("OR", children, start + 1)

    def parse_and(self) -> Node:
        start = self.i
        children = [self.parse_unary()]
        while True:
            self.skip_ws()
            if self.i >= len(self.text) or self.text[self.i] == ")":
                break
            op = self.peek_operator()
            if op == "OR":
                break
            if op == "AND":
                op_pos = self.i
                self.i += 3
                if self.at_end() or self.text[self.i] == ")":
                    raise self.error("AND 뒤에 조건이 없습니다", op_pos)
            children.append(self.parse_unary())
        return children[0] if len(children) == 1 else Group("AND", children, start + 1)

    def parse_unary(self) -> Node:
        self.skip_ws()
        start = self.i
        if self.peek_operator() == "NOT":
            self.i += 3
            if self.at_end():
                raise self.error("NOT 뒤에 조건이 없습니다", start)
            self.enter(start)
            child = self.parse_unary()
            self.depth -= 1
            return Not(child, start + 1)
        if self.text.startswith("-", self.i) and self.i + 1 < len(self.text) and not self.text[self.i + 1].isspace():
            self.i += 1
            self.enter(start)
            child = self.parse_unary()
            self.depth -= 1
            return Not(child, start + 1)
        return self.parse_atom()

    def parse_atom(self) -> Node:
        self.skip_ws()
        start = self.i
        if self.i >= len(self.text):
            raise self.error("조건이 필요합니다")
        char = self.text[self.i]
        if char == "(":
            self.i += 1
            if self.at_end():
                raise self.error("닫는 괄호가 없습니다", start)
            if self.text[self.i] == ")":
                raise self.error("빈 괄호입니다", start)
            self.enter(start)
            node = self.parse_or()
            self.depth -= 1
            self.skip_ws()
            if self.i >= len(self.text) or self.text[self.i] != ")":
                raise self.error("닫는 괄호가 없습니다", start)
            self.i += 1
            return node
        if char == ")":
            raise self.error("여는 괄호 없이 닫는 괄호가 있습니다")
        name_match = _FIELD_NAME_RE.match(self.text, self.i)
        if name_match is not None and name_match.end() < len(self.text) and self.text[name_match.end()] == ":":
            name = name_match.group(0)
            lowered = name.lower()
            if lowered in KNOWN_FIELDS or lowered.startswith("data."):
                field_name = lowered if not lowered.startswith("data.") else "data." + name[5:]
                self.i = name_match.end() + 1
                if self.i >= len(self.text) or self.text[self.i].isspace() or self.text[self.i] == ")":
                    raise self.error(f"{name}: 뒤에 값이 없습니다", start)
                if field_name == "re":
                    return self.term("re", self.parse_re_value(), start)
                value = self.parse_value(allow_list=True)
                return self.term(field_name, value, start)
        if char == "/":
            bare = self.try_bare_regex()
            if bare is not None:
                return self.term("re", bare, start)
        value = self.parse_value(allow_list=False)
        return self.term("kw", value, start)

    def at_boundary(self, index: int) -> bool:
        return index >= len(self.text) or self.text[index].isspace() or self.text[index] == ")"

    def parse_re_value(self) -> Value:
        """``re:/pattern/i`` or ``re:pattern`` (a token)."""
        start = self.i
        if self.text[self.i] == "/":
            value = self.parse_regex()
            if not self.at_boundary(self.i):
                raise self.error("정규식 안의 / 는 \\/ 로 쓰세요(또는 정규식 뒤에 공백을 두세요)", self.i)
            return value
        token = self.parse_token(start)
        return Value("regex", text=token.text, pos=token.pos)

    def try_bare_regex(self) -> Value | None:
        """A bare ``/…/`` (or ``/…/i``) without whitespace or an inner ``/``; else ``None`` (a keyword)."""
        start = self.i
        try:
            value = self.parse_regex()
        except QueryError:
            self.i = start
            return None
        if not self.at_boundary(self.i) or any(char.isspace() for char in value.text):
            self.i = start
            return None
        return value

    def term(self, field_name: str, value: Value, start: int) -> Term:
        self.clauses += 1
        if self.clauses > MAX_CLAUSES:
            raise self.error(f"조건이 너무 많습니다(최대 {MAX_CLAUSES}개)", start)
        return Term(field_name, value, start + 1, self.text[start:self.i])

    def parse_value(self, *, allow_list: bool) -> Value:
        start = self.i
        char = self.text[self.i]
        if char == '"':
            return self.parse_phrase()
        if char == "[":
            return self.parse_range()
        if char == "(" and allow_list:
            return self.parse_list()
        return self.parse_token(start)

    def parse_phrase(self) -> Value:
        start = self.i
        self.i += 1
        out: list[str] = []
        while self.i < len(self.text):
            char = self.text[self.i]
            if char == "\\" and self.i + 1 < len(self.text) and self.text[self.i + 1] in '"\\':
                out.append(self.text[self.i + 1])
                self.i += 2
                continue
            if char == '"':
                self.i += 1
                text = "".join(out)
                if not text.strip():
                    raise self.error("빈 구절입니다", start)
                return Value("phrase", text=text, pos=start + 1)
            out.append(char)
            self.i += 1
        raise self.error("닫는 따옴표가 없습니다", start)

    def parse_regex(self) -> Value:
        start = self.i
        self.i += 1
        out: list[str] = []
        while self.i < len(self.text):
            char = self.text[self.i]
            if char == "\\" and self.i + 1 < len(self.text):
                out.append(self.text[self.i : self.i + 2])
                self.i += 2
                continue
            if char == "/":
                self.i += 1
                flags = ""
                while self.i < len(self.text) and self.text[self.i] in "i":
                    flags += self.text[self.i]
                    self.i += 1
                pattern = "".join(out).replace("\\/", "/")
                if not pattern:
                    raise self.error("빈 정규식입니다", start)
                return Value("regex", text=pattern, flags=flags, pos=start + 1)
            out.append(char)
            self.i += 1
        raise self.error("정규식을 닫는 / 가 없습니다", start)

    def parse_range(self) -> Value:
        start = self.i
        end = self.text.find("]", self.i)
        if end < 0:
            raise self.error("범위를 닫는 ] 가 없습니다", start)
        body = self.text[self.i + 1 : end]
        self.i = end + 1
        if ".." not in body:
            raise self.error("범위는 [시작 .. 끝] 형식이어야 합니다", start)
        low, high = (part.strip() for part in body.split("..", 1))
        if not low and not high:
            raise self.error("범위의 양쪽이 모두 비어 있습니다", start)
        return Value("range", low=low, high=high, pos=start + 1)

    def parse_list(self) -> Value:
        start = self.i
        self.i += 1
        items: list[Value] = []
        while True:
            self.skip_ws()
            if self.i >= len(self.text):
                raise self.error("닫는 괄호가 없습니다", start)
            if self.text[self.i] == ")":
                self.i += 1
                break
            if self.text[self.i] == ",":
                raise self.error("목록에 빈 항목이 있습니다")
            item_start = self.i
            char = self.text[self.i]
            if char == '"':
                item = self.parse_phrase()
            elif char == "[":
                item = self.parse_range()
            else:
                while self.i < len(self.text) and self.text[self.i] not in ",)":
                    self.i += 1
                token = self.text[item_start:self.i].strip()
                if not token:
                    raise self.error("목록에 빈 항목이 있습니다", item_start)
                item = Value("token", text=token, pos=item_start + 1)
            items.append(item)
            if len(items) > MAX_LIST_ITEMS:
                raise self.error(f"목록 항목이 너무 많습니다(최대 {MAX_LIST_ITEMS}개)", item_start)
            self.skip_ws()
            if self.i < len(self.text) and self.text[self.i] == ",":
                self.i += 1
                continue
            if self.i < len(self.text) and self.text[self.i] == ")":
                self.i += 1
                break
            raise self.error("목록 항목은 쉼표로 구분해야 합니다")
        if not items:
            raise self.error("빈 목록입니다", start)
        return Value("list", items=items, pos=start + 1)

    def parse_token(self, start: int) -> Value:
        opened: list[int] = []
        while self.i < len(self.text):
            char = self.text[self.i]
            if char == "(":
                opened.append(self.i)
            elif char == ")":
                if not opened:
                    break
                opened.pop()
            elif char.isspace() and not opened:
                break
            self.i += 1
        if opened:
            raise self.error("닫는 괄호가 없습니다", opened[0])
        token = self.text[start:self.i]
        if not token:
            raise self.error("값이 필요합니다", start)
        return Value("token", text=token, pos=start + 1)


def _collect_terms(node: Node | None, negated: bool, out: list[tuple[Term, bool]]) -> None:
    if node is None:
        return
    if isinstance(node, Term):
        out.append((node, negated))
    elif isinstance(node, Not):
        _collect_terms(node.child, not negated, out)
    else:
        for child in node.children:
            _collect_terms(child, negated, out)


def _check_directives(node: Node | None, *, under_or: bool = False, under_not: bool = False) -> None:
    if node is None:
        return
    if isinstance(node, Term):
        if node.field in DIRECTIVE_FIELDS and (under_or or under_not):
            raise QueryError(f"{node.field}: 조건은 NOT·OR 안에 둘 수 없습니다", node.pos)
        return
    if isinstance(node, Not):
        _check_directives(node.child, under_or=under_or, under_not=True)
        return
    for child in node.children:
        _check_directives(child, under_or=under_or or node.op == "OR", under_not=under_not)


def _validate_terms(terms: list[tuple[Term, bool]], warnings: list[str]) -> None:
    for term, _negated in terms:
        name = term.field
        if name in S2_FIELDS:
            raise QueryError(f"'{name}:' 필드는 검색 S2 단계에서 지원합니다(아직 사용할 수 없음)", term.pos)
        if name in S3_FIELDS:
            raise QueryError(f"'{name}:' 필드는 검색 S3 단계에서 지원합니다(아직 사용할 수 없음)", term.pos)
        value = term.value
        if name == "re" or value.kind == "regex":
            validate_regex(value.text, value.pos or term.pos, value.flags)
        if name == "kw" and value.kind == "token" and value.text.lower() in LOWERCASE_OPERATORS and value.text != value.text.upper():
            message = f"소문자 '{value.text}'는 연산자가 아니라 검색어로 찾습니다. 연산자는 대문자 {value.text.upper()}로 쓰세요"
            if message not in warnings:
                warnings.append(message)
        if name in TEXT_FIELDS and name != "re" and value.kind in {"token", "phrase"}:
            text = nfc(value.text).strip()
            message = ""
            if len(text) == 1:
                message = SHORT_ONE_WARNING
            elif len(text) == 2 and not is_bigram_term(text):
                message = SHORT_TWO_WARNING
            if message and message not in warnings:
                warnings.append(message)
        if name in BOOL_FIELDS and value.kind == "token" and value.text.lower() not in {"true", "false", "yes", "no", "1", "0"}:
            raise QueryError(f"{name}: 값은 true 또는 false여야 합니다", value.pos or term.pos)


def validate_regex(pattern: str, position: int, flags: str = "") -> RegexInfo:
    """Static check + compile (:mod:`.regex_guard`); 400 :class:`QueryError` when unusable."""
    try:
        return analyze_regex(pattern, ignorecase="i" in flags)
    except RegexRejected as exc:
        raise QueryError(exc.reason, position) from exc
    except re.error as exc:
        raise QueryError(f"정규식이 올바르지 않습니다: {exc.msg}", position) from exc
    except (RecursionError, OverflowError) as exc:
        raise QueryError("정규식이 너무 복잡합니다(구조가 너무 깊습니다)", position) from exc


def parse_query(text: str) -> ParsedQuery:
    """Parse ``text``; :class:`QueryError` on any grammar/limit violation."""
    raw = str(text or "")
    if len(raw) > MAX_QUERY_CHARS:
        raise QueryError(f"질의가 너무 깁니다(최대 {MAX_QUERY_CHARS:,}자)")
    if "\x00" in raw:
        raise QueryError("질의에 NUL 문자가 있습니다", raw.index("\x00") + 1)
    for index, char in enumerate(raw):
        if "\ud800" <= char <= "\udfff":
            raise QueryError("질의에 잘못된 유니코드 문자(짝 없는 서로게이트)가 있습니다", index + 1)
    parser = _Parser(nfc(raw))
    root = parser.parse()
    if root is None:
        raise QueryError("검색어가 비어 있습니다")
    terms: list[tuple[Term, bool]] = []
    _collect_terms(root, False, terms)
    _check_directives(root)
    warnings: list[str] = []
    _validate_terms(terms, warnings)
    if all(negated for _term, negated in terms):
        raise QueryError("제외 조건만으로는 검색할 수 없습니다. 찾을 조건을 하나 이상 넣으세요")
    return ParsedQuery(raw=raw, root=root, terms=terms, warnings=warnings)
