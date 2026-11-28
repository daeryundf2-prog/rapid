"""질문 팩: 수사관이 묻는 말 그대로 검색 조건을 만드는 카탈로그.

키워드 팩(`keyword_packs.py`)은 단어 묶음이고, 질문 팩은 "유출 기록 있나?" 같은 한 문장에
그 질문을 확인할 때 보는 것들을 묶어 둔 것이다: 키워드 팩, 추가 키워드, 볼 컬렉션,
아티팩트 계열, 윈도우 이벤트 ID, 참고 출처.

카탈로그는 확장된다. 사건마다, 기관마다 쓰는 말이 다르므로

* `RAPIDTRIAGE_QUESTION_PACKS` 에 파일이나 폴더를 넣거나(`os.pathsep` 로 여러 개),
* `~/.rapidtriage/question-packs/*.json` 에 파일을 두면

내장 카탈로그에 더해진다. 같은 `id` 면 사용자 파일이 내장 항목을 대체하고, 어느 쪽에서
왔는지는 각 행의 `source_ref` 에 남는다.

다른 도구에서 뽑아 둔 키워드 목록(Autopsy 키워드 리스트, 기관 표준 단어집 등)도 그대로
쓸 수 있다: `{"유출 의심 단어": ["mega.nz", "대외비"]}` 처럼 이름→단어 목록인 JSON 은
질문 팩 한 건으로 변환된다.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path

from .keyword_packs import BUILTIN_KEYWORD_PACKS
from .question_catalog import BUILTIN_QUESTION_PACKS

QUESTION_PACK_PROFILE_VERSION = "question-pack-v1"
QUESTION_PACK_ENV = "RAPIDTRIAGE_QUESTION_PACKS"
USER_QUESTION_PACK_DIR = Path.home() / ".rapidtriage" / "question-packs"

#: 답이 아니라 출발점이라는 점을 화면과 보고서에 그대로 싣기 위한 문구.
QUESTION_PACK_LIMITS = [
    "질문 팩은 조사 출발점이다 — 결과가 없다고 해서 그 행위가 없었다는 뜻은 아니다",
    "키워드와 이벤트 ID 는 한국어·사내 용어·사건별 표현을 담지 못한다",
    "사건에 맞는 단어를 더해 쓰고, 쓴 팩 이름과 추가 단어를 기록으로 남긴다",
]

COLLECTIONS = frozenset(
    {"files", "docs", "artifacts", "timeline", "indicators", "search", "derived", "registry"}
)


class QuestionPackError(ValueError):
    """질문 팩 입력을 읽을 수 없을 때."""


def stable_question_pack_sha256(payload: object) -> str:
    return hashlib.sha256(json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()


def normalize_question_pack(raw: Mapping[str, object], *, source_ref: str) -> dict[str, object]:
    """한 건을 검사하고 빠진 칸을 채운다. `id` 와 `question` 은 필수."""
    pack_id = str(raw.get("id") or "").strip()
    question = str(raw.get("question") or "").strip()
    if not pack_id:
        raise QuestionPackError(f"질문 팩에 id 가 없습니다 ({source_ref})")
    if not question:
        raise QuestionPackError(f"질문 팩 {pack_id} 에 question 이 없습니다 ({source_ref})")
    keyword_packs = [str(name).strip() for name in _as_list(raw.get("keyword_packs")) if str(name).strip()]
    unknown = [name for name in keyword_packs if name not in BUILTIN_KEYWORD_PACKS]
    if unknown:
        raise QuestionPackError(f"질문 팩 {pack_id}: 없는 키워드 팩 {', '.join(unknown)} ({source_ref})")
    collections = [str(name).strip() for name in _as_list(raw.get("collections")) if str(name).strip()]
    bad = [name for name in collections if name not in COLLECTIONS]
    if bad:
        raise QuestionPackError(f"질문 팩 {pack_id}: 없는 컬렉션 {', '.join(bad)} ({source_ref})")
    pack = {
        "id": pack_id,
        "question": question,
        "category": str(raw.get("category") or "기타").strip(),
        "keyword_packs": keyword_packs,
        "keywords": _unique_strings(raw.get("keywords")),
        "collections": collections or ["search"],
        "artifact_kinds": _unique_strings(raw.get("artifact_kinds")),
        "event_ids": [str(value).strip() for value in _as_list(raw.get("event_ids")) if str(value).strip()],
        "extensions": [_extension(value) for value in _as_list(raw.get("extensions")) if str(value).strip()],
        "references": _unique_strings(raw.get("references")),
        "note": str(raw.get("note") or "").strip(),
        "source_ref": source_ref,
    }
    pack["expanded_keywords"] = expand_keywords(pack)
    pack["keyword_count"] = len(pack["expanded_keywords"])
    pack["pack_sha256"] = stable_question_pack_sha256({k: v for k, v in pack.items() if k != "source_ref"})
    return pack


def expand_keywords(pack: Mapping[str, object]) -> list[str]:
    """키워드 팩을 펼쳐 질문 자체 키워드와 합친다(중복은 대소문자 무시로 제거, 순서 유지)."""
    output: list[str] = []
    seen: set[str] = set()
    for name in _as_list(pack.get("keyword_packs")):
        for keyword in BUILTIN_KEYWORD_PACKS.get(str(name), []):
            _add(output, seen, keyword)
    for keyword in _as_list(pack.get("keywords")):
        _add(output, seen, keyword)
    for event_id in _as_list(pack.get("event_ids")):
        _add(output, seen, event_id)
    return output


def load_question_packs(extra_paths: Sequence[str | Path] | None = None) -> list[dict[str, object]]:
    """내장 카탈로그 + 사용자 파일. 같은 id 는 뒤에 읽은 사용자 파일이 대체한다."""
    packs: dict[str, dict[str, object]] = {}
    for raw in BUILTIN_QUESTION_PACKS:
        pack = normalize_question_pack(raw, source_ref="builtin")
        packs[str(pack["id"])] = pack
    for path in _user_pack_files(extra_paths):
        for raw in read_question_pack_file(path):
            pack = normalize_question_pack(raw, source_ref=str(path))
            packs[str(pack["id"])] = pack
    return sorted(packs.values(), key=lambda pack: (str(pack["category"]), str(pack["id"])))


def read_question_pack_file(path: Path) -> list[dict[str, object]]:
    """질문 팩 JSON 한 파일. 우리 스키마(목록/`packs`)도, 이름→단어 목록도 받는다."""
    resolved = Path(path).expanduser()
    try:
        payload = json.loads(resolved.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise QuestionPackError(f"질문 팩 파일이 JSON 이 아닙니다: {resolved}") from exc
    except OSError as exc:
        raise QuestionPackError(f"질문 팩 파일을 읽을 수 없습니다: {resolved}") from exc
    return question_packs_from_payload(payload, origin=resolved.stem)


def question_packs_from_payload(payload: object, *, origin: str = "custom") -> list[dict[str, object]]:
    if isinstance(payload, Mapping) and isinstance(payload.get("packs"), list):
        return [row for row in payload["packs"] if isinstance(row, Mapping)]
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, Mapping)]
    if isinstance(payload, Mapping):
        # 다른 도구의 "이름 → 단어 목록" 내보내기: 질문 한 건으로 옮긴다.
        rows = []
        for name, keywords in payload.items():
            if not isinstance(keywords, list):
                raise QuestionPackError(f"질문 팩 {name}: 단어 목록이어야 합니다")
            rows.append(
                {
                    "id": f"{origin}-{_slug(str(name))}",
                    "question": str(name),
                    "category": "가져온 목록",
                    "keywords": keywords,
                    "collections": ["search"],
                    "references": [f"imported:{origin}"],
                }
            )
        return rows
    raise QuestionPackError("질문 팩 JSON 은 목록이거나 이름→단어 목록이어야 합니다")


def question_pack_catalog(extra_paths: Sequence[str | Path] | None = None) -> dict[str, object]:
    """API·CLI 가 그대로 내보내는 카탈로그(목록 + 분류 + 출처 + 해시)."""
    packs = load_question_packs(extra_paths)
    categories = sorted({str(pack["category"]) for pack in packs})
    core = {
        "profile_version": QUESTION_PACK_PROFILE_VERSION,
        "pack_count": len(packs),
        "builtin_count": sum(1 for pack in packs if pack["source_ref"] == "builtin"),
        "custom_count": sum(1 for pack in packs if pack["source_ref"] != "builtin"),
        "categories": categories,
        "limits": list(QUESTION_PACK_LIMITS),
        "pack_hashes": [str(pack["pack_sha256"]) for pack in packs],
    }
    return {**core, "packs": packs, "catalog_sha256": stable_question_pack_sha256(core)}


def _user_pack_files(extra_paths: Sequence[str | Path] | None) -> list[Path]:
    candidates: list[str | Path] = []
    env_value = os.environ.get(QUESTION_PACK_ENV, "")
    candidates.extend(part for part in env_value.split(os.pathsep) if part.strip())
    candidates.append(USER_QUESTION_PACK_DIR)
    candidates.extend(extra_paths or [])
    files: list[Path] = []
    for candidate in candidates:
        path = Path(candidate).expanduser()
        if path.is_dir():
            files.extend(sorted(path.glob("*.json")))
        elif path.is_file():
            files.append(path)
    return files


def _as_list(value: object) -> list[object]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return list(value)
    return [value]


def _unique_strings(value: object) -> list[str]:
    output: list[str] = []
    seen: set[str] = set()
    for item in _as_list(value):
        _add(output, seen, item)
    return output


def _add(output: list[str], seen: set[str], value: object) -> None:
    text = str(value or "").strip()
    if not text:
        return
    key = text.casefold()
    if key in seen:
        return
    seen.add(key)
    output.append(text)


def _extension(value: object) -> str:
    text = str(value or "").strip().lower()
    return text if text.startswith(".") else f".{text}"


def _slug(value: str) -> str:
    kept = [char if char.isalnum() else "-" for char in value.strip().lower()]
    return "".join(kept).strip("-") or "pack"


def question_pack_ids(packs: Iterable[Mapping[str, object]]) -> list[str]:
    return [str(pack.get("id") or "") for pack in packs]
