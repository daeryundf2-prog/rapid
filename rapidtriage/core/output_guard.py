"""Never write run / tool output inside the evidence (forensic integrity, R7).

One shared rule for every writer that takes an evidence path and an output path
(core run entry, the web job store, API runs / cases / retry / output-check, CLI):

* output == evidence                -> refused (``OUTPUT_INSIDE_EVIDENCE``)
* output inside the evidence folder -> refused (``OUTPUT_INSIDE_EVIDENCE``)
  (an output "inside" a file evidence, e.g. ``image.E01/out``, is refused too)
* evidence inside the output folder -> refused (``EVIDENCE_INSIDE_OUTPUT``)

Evidence inside the output is refused as well (decision, not an oversight): the
output folder is a writable workspace. Its fixed child names (``artifacts/``,
``files-extract/``, ``carving/``, ``analyses/`` ...), ``--overwrite`` / resume
cleanup and stage rebuilds act on paths under it, so read-only semantics for an
evidence tree nested there cannot be guaranteed. A case folder (``case_root``)
may hold the evidence: only the per-run subfolder under it is the output, and
that subfolder is checked by this rule.

Paths are compared after ``realpath`` (symlinks and Windows junctions resolved,
``\\\\?\\`` prefixes dropped) and ``normcase`` (case-insensitive on Windows).
Existing ancestors are additionally compared with ``os.path.samefile`` so an
alias the lexical form cannot see (``subst`` drive, 8.3 short name, a second
mount of the same folder) is still caught.
"""

from __future__ import annotations

import os
from collections.abc import Iterable
from pathlib import Path

OUTPUT_INSIDE_EVIDENCE = "OUTPUT_INSIDE_EVIDENCE"
EVIDENCE_INSIDE_OUTPUT = "EVIDENCE_INSIDE_OUTPUT"
OUTPUT_DIR_REQUIRED = "OUTPUT_DIR_REQUIRED"

OUTPUT_INSIDE_EVIDENCE_MESSAGE = (
    "출력 위치가 증거 경로 안(또는 증거와 같은 경로)입니다. 증거에는 아무것도 쓰지 않습니다. "
    "증거 밖의 출력 폴더를 지정하세요"
)
EVIDENCE_INSIDE_OUTPUT_MESSAGE = (
    "증거가 출력 폴더 안에 있습니다. 출력 폴더는 덮어쓰기·정리 대상이라 증거를 담을 수 없습니다. "
    "증거 밖의 다른 출력 폴더를 지정하세요"
)

#: CLI help / error text (Korean + English).
CLI_OUTPUT_INSIDE_EVIDENCE = (
    OUTPUT_INSIDE_EVIDENCE_MESSAGE
    + " / Output must not be the evidence path or inside it; choose an output folder outside the evidence."
)
CLI_EVIDENCE_INSIDE_OUTPUT = (
    EVIDENCE_INSIDE_OUTPUT_MESSAGE
    + " / The evidence is inside the output folder; choose an output folder that does not contain the evidence."
)

_MESSAGES = {
    OUTPUT_INSIDE_EVIDENCE: OUTPUT_INSIDE_EVIDENCE_MESSAGE,
    EVIDENCE_INSIDE_OUTPUT: EVIDENCE_INSIDE_OUTPUT_MESSAGE,
}
_CLI_MESSAGES = {
    OUTPUT_INSIDE_EVIDENCE: CLI_OUTPUT_INSIDE_EVIDENCE,
    EVIDENCE_INSIDE_OUTPUT: CLI_EVIDENCE_INSIDE_OUTPUT,
}


class OutputInsideEvidenceError(ValueError):
    """An output path overlaps an evidence path (HTTP 422 with ``code``; CLI usage error)."""

    def __init__(self, code: str, *, output: Path | str, evidence: Path | str) -> None:
        self.code = code
        self.output = str(output)
        self.evidence = str(evidence)
        self.message = _MESSAGES[code]
        super().__init__(f"{self.message}: 출력 {self.output} / 증거 {self.evidence}")

    @property
    def cli_message(self) -> str:
        return f"{_CLI_MESSAGES[self.code]} (output: {self.output}; evidence: {self.evidence})"

    def to_detail(self) -> dict[str, str]:
        """HTTP ``detail`` body: the console shows ``message``; ``code`` is stable."""
        return {"code": self.code, "message": str(self), "output": self.output, "evidence": self.evidence}


def canonical_path(path: Path | str) -> str:
    """Real, normalized, case-folded (Windows) absolute path text for comparisons."""
    text = os.path.realpath(os.path.abspath(os.path.expanduser(os.fspath(path))))
    if text.startswith("\\\\?\\UNC\\"):
        text = "\\\\" + text[8:]
    elif text.startswith("\\\\?\\"):
        text = text[4:]
    return os.path.normcase(os.path.normpath(text))


def _within(child: str, parent: str) -> bool:
    if child == parent:
        return True
    prefix = parent if parent.endswith(os.sep) else parent + os.sep
    return child.startswith(prefix)


def _existing_chain(path: str) -> list[str]:
    """``path`` and its ancestors that exist (deepest first)."""
    chain: list[str] = []
    current = path
    while True:
        if os.path.exists(current):
            chain.append(current)
        parent = os.path.dirname(current)
        if not parent or parent == current:
            return chain
        current = parent


def _same(left: str, right: str) -> bool:
    try:
        return os.path.samefile(left, right)
    except OSError:
        return False


def _alias_within(child: str, parent: str) -> bool:
    """``child`` (or one of its existing ancestors) is the same file-system object as ``parent``."""
    if not os.path.exists(parent):
        return False
    return any(_same(candidate, parent) for candidate in _existing_chain(child))


def output_evidence_conflict(output: Path | str, evidence: Path | str) -> str | None:
    """Error code of the overlap between ``output`` and ``evidence`` (``None`` when separate)."""
    out = canonical_path(output)
    ev = canonical_path(evidence)
    if _within(out, ev) or _alias_within(out, ev):
        return OUTPUT_INSIDE_EVIDENCE
    if _within(ev, out) or _alias_within(ev, out):
        return EVIDENCE_INSIDE_OUTPUT
    return None


def check_output_outside_evidence(
    output: Path | str,
    evidence: Iterable[Path | str | None],
    *,
    allow_evidence_inside: bool = False,
) -> None:
    """Raise :class:`OutputInsideEvidenceError` when ``output`` overlaps any evidence path.

    ``allow_evidence_inside`` (a case folder, not a run output) only refuses an
    output equal to / inside the evidence.
    """
    for item in evidence:
        if item is None or not str(item).strip():
            continue
        code = output_evidence_conflict(output, item)
        if code is None or (allow_evidence_inside and code == EVIDENCE_INSIDE_OUTPUT):
            continue
        raise OutputInsideEvidenceError(code, output=output, evidence=item)


def output_evidence_problem(
    output: Path | str,
    evidence: Iterable[Path | str | None],
    *,
    allow_evidence_inside: bool = False,
) -> OutputInsideEvidenceError | None:
    """The error :func:`check_output_outside_evidence` would raise (``None`` when allowed)."""
    try:
        check_output_outside_evidence(output, evidence, allow_evidence_inside=allow_evidence_inside)
    except OutputInsideEvidenceError as exc:
        return exc
    return None
