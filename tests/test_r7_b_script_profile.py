"""R7 lane B: writing-system profile (``script_profile``) and ``language_hint`` of extracted
documents -- synthetic HWP, DOCX and EML with a known mix of Korean, Chinese, Japanese and English."""

from __future__ import annotations

import tempfile
import unittest
import zipfile
from pathlib import Path

from rapidtriage.core.doc_text import language_hint, script_profile
from rapidtriage.core.docs import extract_document_text
from tests.test_parser_quality_core import build_hwp

# Letters per script in one block (spaces/punctuation are not letters).
HANGUL_WORD = "계약해지통보"  # 6
HAN_WORD = "契約解除"  # 4
KANA_WORD = "おしらせ"  # 4
LATIN_WORD = "notice"  # 6


def mixed_text(hangul: int, han: int, kana: int, latin: int) -> str:
    """Words of each script, ``n`` words each, space separated, in sentences."""
    words = [HANGUL_WORD] * hangul + [HAN_WORD] * han + [KANA_WORD] * kana + [LATIN_WORD] * latin
    return "\n".join(" ".join(words[i : i + 8]) + "." for i in range(0, len(words), 8))


def expected(hangul: int, han: int, kana: int, latin: int) -> dict[str, float]:
    counts = {"hangul": hangul * 6, "han": han * 4, "kana": kana * 4, "latin": latin * 6}
    total = sum(counts.values())
    return {name: count / total for name, count in counts.items()}


def docx_bytes(text: str) -> bytes:
    import io

    paragraphs = "".join(f"<w:p><w:r><w:t>{line}</w:t></w:r></w:p>" for line in text.splitlines())
    document = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        f"<w:body>{paragraphs}</w:body></w:document>"
    )
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>')
        archive.writestr("word/document.xml", document)
    return buffer.getvalue()


def eml_bytes(text: str) -> bytes:
    headers = (
        "From: sender@example.com\r\nTo: receiver@example.com\r\nSubject: =?UTF-8?B?7JWI64K0?=\r\n"
        "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n"
    )
    return headers.encode("ascii") + text.replace("\n", "\r\n").encode("utf-8")


MIXES = {
    "korean": (40, 5, 0, 5),
    "japanese": (0, 20, 30, 4),
    "chinese": (0, 50, 0, 2),
    "english": (2, 0, 0, 40),
    "mixed": (20, 10, 10, 15),
}
HINTS = {"korean": "ko", "japanese": "ja", "chinese": "zh", "english": "en", "mixed": "mixed"}


class ScriptProfileTests(unittest.TestCase):
    def test_documents_within_two_percent(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name, mix in MIXES.items():
                text = mixed_text(*mix)
                files = {
                    f"{name}.hwp": ("hwp", build_hwp(text)),
                    f"{name}.docx": ("docx", docx_bytes(text)),
                    f"{name}.eml": ("eml", eml_bytes(text)),
                }
                want = expected(*mix)
                for filename, (kind, data) in files.items():
                    path = root / filename
                    path.write_bytes(data)
                    result = extract_document_text(path, kind)
                    self.assertEqual(result.status, "ok", (filename, result.reason))
                    profile = result.script_profile
                    for script, share in want.items():
                        self.assertAlmostEqual(profile[script], share, delta=0.02, msg=f"{filename} {script}: {profile}")
                    self.assertEqual(result.language_hint, HINTS[name], (filename, profile))
                    self.assertEqual(result.as_metadata()["language_hint"], HINTS[name])

    def test_hints(self) -> None:
        cases = {
            "근로계약 해지 통보서를 보냅니다 확인 부탁드립니다": "ko",
            "契約の解除についてお知らせします。ご確認ください": "ja",
            "合同解除通知书请查收并确认收到谢谢合作愉快": "zh",
            "Please review the attached termination notice today": "en",
            "Пожалуйста проверьте уведомление о расторжении": "ru",
            "근로계약서 해지 통보 확인 부탁 notice termination": "mixed",
            "짧은 글": "",
        }
        for text, hint in cases.items():
            self.assertEqual(language_hint(script_profile(text)), hint, text)

    def test_addresses_and_paths_are_not_prose(self) -> None:
        text = "보낸 사람 kim.tester@example.com 첨부 C:\\Users\\kim\\Desktop\\report.docx https://example.com/a 결제 내역을 꼭 확인해 주시기 바랍니다"
        profile = script_profile(text)
        self.assertEqual(profile["latin"], 0.0)
        self.assertEqual(language_hint(profile), "ko")
        self.assertEqual(script_profile(""), {})


if __name__ == "__main__":
    unittest.main()
