"""Markdown encoding of evidence values for the case reports.

The report markdown is the single source of the HTML, DOCX and PDF exports, so
a value taken from evidence (a file name, a path, a note) must survive it
verbatim: two names that differ by one backtick or asterisk must print
differently in every format. Values are therefore encoded, never pasted:

* :func:`markdown_code` writes a CommonMark code span whose backtick fence is
  longer than any backtick run inside the value (padded with a space when the
  value starts or ends with a backtick or a space), so its content is literal.
* :func:`markdown_text` backslash-escapes the inline markup characters of
  plain text (CommonMark backslash escapes).

:func:`inline_segments` is the matching reader the exporters use.
"""

from __future__ import annotations

import re
import string

ASCII_PUNCTUATION = frozenset(string.punctuation)
# Code spans are one line; control characters are shown as Unicode control
# pictures (U+2400 block) instead of breaking the line or vanishing.
CONTROL_PICTURES = {code: 0x2400 + code for code in range(0x20)} | {0x7F: 0x2421}


def markdown_code(value: object) -> str:
    text = str(value).translate(CONTROL_PICTURES)
    if not text:
        return ""
    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    fence = "`" * (longest + 1)
    pad = ""
    if text.startswith("`") or text.endswith("`") or (text.startswith(" ") and text.endswith(" ") and text.strip(" ")):
        pad = " "
    return f"{fence}{pad}{text}{pad}{fence}"


def markdown_text(value: object) -> str:
    text = str(value)
    out: list[str] = []
    for index, char in enumerate(text):
        if char in "`*":
            out.append("\\" + char)
        elif char == "\\" and (index + 1 == len(text) or text[index + 1] in ASCII_PUNCTUATION):
            out.append("\\\\")
        else:
            out.append(char)
    return "".join(out)


def inline_segments(value: str) -> list[tuple[str, str]]:
    """``(kind, text)`` runs of one markdown line: ``text``, ``code`` or ``strong``.

    Code spans follow CommonMark (a fence closes only on a run of the same
    length; one surrounding space is stripped when both are present), backslash
    escapes apply outside code spans, and ``**...**`` marks strong text.
    """
    segments: list[tuple[str, str]] = []
    buffer: list[str] = []

    def flush() -> None:
        if buffer:
            segments.append(("text", "".join(buffer)))
            buffer.clear()

    length = len(value)
    index = 0
    while index < length:
        char = value[index]
        if char == "\\" and index + 1 < length and value[index + 1] in ASCII_PUNCTUATION:
            buffer.append(value[index + 1])
            index += 2
            continue
        if char == "`":
            run_end = index
            while run_end < length and value[run_end] == "`":
                run_end += 1
            close = find_closing_fence(value, run_end, run_end - index)
            if close is None:
                buffer.append(value[index:run_end])
                index = run_end
                continue
            content = value[run_end:close]
            if len(content) >= 2 and content[0] == " " and content[-1] == " " and content.strip(" "):
                content = content[1:-1]
            flush()
            segments.append(("code", content))
            index = close + (run_end - index)
            continue
        if value.startswith("**", index):
            close = find_strong_close(value, index + 2)
            if close is not None:
                flush()
                segments.append(("strong", unescape(value[index + 2 : close])))
                index = close + 2
                continue
        buffer.append(char)
        index += 1
    flush()
    return segments


def find_closing_fence(value: str, start: int, size: int) -> int | None:
    index = start
    while index < len(value):
        if value[index] != "`":
            index += 1
            continue
        run_end = index
        while run_end < len(value) and value[run_end] == "`":
            run_end += 1
        if run_end - index == size:
            return index
        index = run_end
    return None


def find_strong_close(value: str, start: int) -> int | None:
    index = start
    while index < len(value):
        char = value[index]
        if char == "\\" and index + 1 < len(value):
            index += 2
            continue
        if char == "`":
            return None
        if char == "*":
            return index if value.startswith("**", index) and index > start else None
        index += 1
    return None


def unescape(value: str) -> str:
    return re.sub(r"\\([!-/:-@\[-`{-~])", r"\1", value)
