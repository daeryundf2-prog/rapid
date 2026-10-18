"""Fixtures of ``rapidtriage.core.triage_rules.documents`` (see ``tests.triage_cases``).

Rows are ``generic-documents`` ``document-metadata-risk`` rows shaped like
``collect_document_metadata_risk`` (top-level normalized fields + profiles).
"""

from __future__ import annotations

DOCS = r"C:\Users\analyst\Documents"


def doc(name: str, **details: object) -> dict[str, object]:
    path = rf"{DOCS}\{name}"
    family = name.rsplit(".", 1)[-1]
    base: dict[str, object] = {
        "parser": "document-metadata-risk",
        "source_path": path,
        "document_family": family,
        "container_format": "pdf" if family == "pdf" else "ooxml-zip",
        "encrypted": False,
        "macro_profile": {"macro_present": False, "macro_paths": [], "macro_path_count": 0, "macro_scan_status": "not-detected"},
        "external_reference_candidates": [],
        "risk_flags": ["document-metadata-profile"],
    }
    base.update(details)
    return {"kind": "generic-documents", "row": {"artifact_type": "document-metadata-risk", "path": path, "details": base}}


def macros(*paths: str) -> dict[str, object]:
    return {"macro_present": bool(paths), "macro_paths": list(paths), "macro_path_count": len(paths), "macro_scan_status": "vba-project-present" if paths else "not-detected"}


def files_row(name: str, fs_modified_at: str) -> dict[str, object]:
    return {"files": "candidates", "row": {"path": rf"{DOCS}\{name}", "name": name, "size": 20480, "fs_modified_at": fs_modified_at}}


PERSON = {"author": "Kim Analyst", "last_modified_by": "Kim Analyst", "created_at": "2024-04-01T09:00:00Z", "modified_at": "2024-04-02T09:00:00Z"}
HWPX_DEFAULT_SCRIPTS = ("Scripts/headerScripts.js", "Scripts/sourceScripts.js")

CASES = {
    "documents.lastsaved_ne_author": {
        "positive": {"rows": [doc("proposal.docx", **{**PERSON, "last_modified_by": "Lee Reviewer"})], "flagged": [0]},
        # Same person, different spacing/case in the two properties.
        "negative": {"rows": [doc("proposal.docx", **{**PERSON, "author": "Kim  Analyst", "last_modified_by": "kim analyst"})], "flagged": []},
    },
    "documents.edit_time_zero_many_rev": {
        "positive": {"rows": [doc("contract.docx", **PERSON, total_edit_time_seconds=0, revision="27")], "flagged": [0]},
        # Freshly saved twice, and a long-edited document with many revisions.
        "negative": {
            "rows": [
                doc("memo.docx", **PERSON, total_edit_time_seconds=0, revision="2"),
                doc("thesis.docx", **PERSON, total_edit_time_seconds=2700, revision="31"),
            ],
            "flagged": [],
        },
    },
    "documents.created_after_modified": {
        "positive": {"rows": [doc("minutes.docx", **{**PERSON, "created_at": "2024-05-03T10:00:00Z", "modified_at": "2024-05-01T09:00:00Z"})], "flagged": [0]},
        # Same-day PDF: zone-naive CreationDate (KST read as UTC) vs UTC ModDate, ~9 h apart.
        "negative": {
            "rows": [doc("statement.pdf", author="Kim Analyst", application="Microsoft Word", created_at="2024-05-01T18:00:00", modified_at="2024-05-01T09:05:00Z")],
            "flagged": [],
        },
    },
    "documents.modified_vs_fs": {
        "positive": {
            "rows": [files_row("budget.xlsx", "2024-05-01T10:00:00Z"), doc("budget.xlsx", **{**PERSON, "modified_at": "2022-01-10T09:00:00Z"})],
            "flagged": [1],
        },
        # Saved a few hours after the last internal save time (zone-naive internal time).
        "negative": {
            "rows": [files_row("budget.xlsx", "2024-05-01T10:00:00Z"), doc("budget.xlsx", **{**PERSON, "modified_at": "2024-05-01T08:30:00Z"})],
            "flagged": [],
        },
    },
    "documents.meta_tool_name_user": {
        "positive": {"rows": [doc("export.docx", author="python-docx", last_modified_by="python-docx", created_at="2024-04-01T09:00:00Z")], "flagged": [0]},
        # Converted with a library (Application names it) but the properties name a person.
        "negative": {"rows": [doc("converted.docx", **PERSON, application="Aspose.Words for .NET 23.1")], "flagged": []},
    },
    "documents.macro_or_ole": {
        "positive": {
            "rows": [
                doc("invoice.doc", **PERSON, macro_profile=macros("Macros/VBA/ThisDocument", "Macros/VBA/_VBA_PROJECT"), risk_flags=["document-metadata-profile", "document-macro-present"]),
                doc("form.hwpx", **PERSON, macro_profile=macros(*HWPX_DEFAULT_SCRIPTS, "Scripts/userScript.js"), risk_flags=["document-metadata-profile", "document-macro-present"]),
            ],
            "flagged": [0, 1],
        },
        # Every Hancom-written HWPX carries these two default script parts.
        "negative": {
            "rows": [doc("notice.hwpx", **PERSON, macro_profile=macros(*HWPX_DEFAULT_SCRIPTS), risk_flags=["document-metadata-profile", "document-author-metadata", "document-macro-present"])],
            "flagged": [],
        },
    },
    "documents.external_template_url": {
        "positive": {
            "rows": [
                doc(
                    "letter.docx",
                    **PERSON,
                    template="Normal.dotm",
                    external_reference_candidates=[
                        {
                            "relationship_type": "http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate",
                            "target": "https://templates.example.net/t/letter.dotm",
                            "target_mode": "External",
                        }
                    ],
                )
            ],
            "flagged": [0],
        },
        # Local template from the user's Templates folder.
        "negative": {"rows": [doc("letter.docx", **PERSON, template=r"C:\Users\analyst\AppData\Roaming\Microsoft\Templates\Report.dotx")], "flagged": []},
    },
    "documents.printed_present": {
        "positive": {"rows": [doc("report.docx", **PERSON, last_printed_at="2024-04-30T15:00:00Z")], "flagged": [0]},
        # OLE "never printed" placeholder (FILETIME 0 -> 1601).
        "negative": {"rows": [doc("report.doc", **PERSON, last_printed_at="1601-01-01T00:00:00+00:00")], "flagged": []},
    },
    "documents.pdf_creator_producer_odd": {
        # Producer only lives in the normalized metadata (the parser does not lift it).
        "positive": {
            "rows": [
                doc(
                    "agreement.pdf",
                    author="Kim Analyst",
                    application="Microsoft® Word for Microsoft 365",
                    metadata_profile={"document_family": "pdf", "normalized_metadata": {"application": "Microsoft® Word for Microsoft 365", "producer": "iLovePDF"}},
                )
            ],
            "flagged": [0],
        },
        # Word's own "Save as PDF" and Hancom's PDF export.
        "negative": {
            "rows": [
                doc("agreement.pdf", application="Microsoft® Word for Microsoft 365", producer="Microsoft® Word for Microsoft 365"),
                doc("notice.pdf", application="Hwp 2020 11.0.0.5178", producer="Hancom PDF 1.3.0.538"),
            ],
            "flagged": [],
        },
    },
    "documents.pdf_incremental_update": {
        "positive": {"rows": [doc("signed.pdf", application="Microsoft Word", pdf_eof_count=3)], "flagged": [0]},
        # Single revision PDFs.
        "negative": {
            "rows": [
                doc("plain.pdf", application="Microsoft Word", pdf_eof_count=1),
                doc("export.pdf", application="Microsoft Word", incremental_update_count=0),
            ],
            "flagged": [],
        },
    },
    "documents.tracked_authors_many": {
        "positive": {"rows": [doc("draft.docx", **PERSON, tracked_change_authors=["Kim Analyst", "Lee Reviewer"])], "flagged": [0]},
        # Only the author's own tracked changes (different case).
        "negative": {"rows": [doc("draft.docx", **PERSON, tracked_change_authors=["kim analyst"])], "flagged": []},
    },
    "documents.meta_scrubbed": {
        "positive": {
            "rows": [doc("leak.docx", created_at="2024-04-01T09:00:00Z", modified_at="2024-04-02T09:00:00Z", application="Microsoft Office Word", author_candidates=[])],
            "flagged": [0],
        },
        # HWP 3.0 header-only row: properties never parsed, so empty authors mean nothing.
        "negative": {"rows": [doc("old.hwp", document_family="hwp", container_format="hwp3-binary")], "flagged": []},
    },
}
