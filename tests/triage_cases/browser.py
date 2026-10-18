"""Fixtures of ``rapidtriage.core.triage_rules.browser`` (see ``tests.triage_cases``)."""

from __future__ import annotations

from rapidtriage.artifacts.windows.web_upload import (
    CATEGORIES,
    load_upload_patterns,
    match_upload_url,
)

PROFILE = r"C:\Users\alice\AppData\Local\Google\Chrome\User Data\Default"


def browser_row(artifact_type: str, source: str = "History", **details: object) -> dict[str, object]:
    base: dict[str, object] = {"browser": "chrome", "profile": "Default", "source_path": PROFILE + "\\" + source}
    base.update(details)
    return {"kind": "browser", "row": {"artifact_type": artifact_type, "path": base["source_path"], "details": base}}


def download(**details: object) -> dict[str, object]:
    base: dict[str, object] = {
        "start_time": "2024-05-01T10:00:00Z",
        "target_path": r"C:\Users\alice\Downloads\report.pdf",
        "source_url": "https://files.example.com/report.pdf",
        "tab_url": "https://intranet.example.com/docs",
        "danger_type": 0,
        "danger_type_name": "NOT_DANGEROUS",
    }
    base.update(details)
    return browser_row("browser-download", **base)


def listed(path: str) -> dict[str, object]:
    return {"files": "inventory", "row": {"path": path, "name": path.rsplit("\\", 1)[-1], "size": 1024}}


def visit(timestamp: str, url: str = "https://www.example.com/", **details: object) -> dict[str, object]:
    return browser_row("browser-visit", timestamp=timestamp, url=url, **details)


def history(url_id: int, url: str = "https://www.example.com/") -> dict[str, object]:
    return browser_row("browser-history", url_id=url_id, url=url, last_visit_time="2024-05-01T10:00:00Z")


def prefetch_activity(days: list[str], per_day: int = 50) -> dict[str, object]:
    """One Prefetch row whose run times give ``per_day`` activity events on each of ``days``."""
    times = [f"{day}T{9 + index // 60:02d}:{index % 60:02d}:00Z" for day in days for index in range(per_day)]
    return {
        "kind": "prefetch",
        "row": {"artifact_type": "prefetch-file", "path": r"C:\Windows\Prefetch\EXCEL.EXE-1A2B3C4D.pf", "details": {"executable_name": "EXCEL.EXE", "last_run_times": times}},
    }


def extension(**details: object) -> dict[str, object]:
    base: dict[str, object] = {
        "name": "Sample Helper",
        "extension_id": "abcdefghijklmnopabcdefghijklmnop",
        "version": "1.0.0",
        "from_webstore": True,
        "was_installed_by_default": False,
        "location_name": "INTERNAL",
        "permissions": ["storage"],
    }
    base.update(details)
    return browser_row("browser-extension", "Secure Preferences", **base)


def upload_candidate(**details: object) -> dict[str, object]:
    base: dict[str, object] = {
        "timestamp": "2024-05-01T10:00:00Z",
        "method": "GET",
        "source_artifact_type": "browser-cache-entry",
        "match_pattern_id": "fixture",
    }
    base.update(details)
    return browser_row("web-upload-candidate", r"Cache\Cache_Data\data_1", **base)


def pattern_candidate(url: str, method: str = "GET", **details: object) -> dict[str, object]:
    """The ``web-upload-candidate`` row the scanner builds for ``url`` (service/category/strength
    from ``web_upload_patterns.yaml``), so the cases follow the shipped patterns."""
    matched = match_upload_url(url, method, load_upload_patterns())
    assert matched is not None, f"no upload pattern matches {url}"
    pattern, strength = matched
    assert pattern.category in CATEGORIES
    return upload_candidate(
        url=url,
        method=method,
        service=pattern.service,
        category=pattern.category,
        strength=strength,
        match_pattern_id=pattern.id,
        **details,
    )


CASES = {
    "browser.dl_from_filesharing": {
        "positive": {
            "rows": [download(source_url="https://download.example-cdn.net/f/8a7b", tab_url="https://mega.nz/file/AbCdEf#key", target_path=r"C:\Users\alice\Downloads\archive.7z")],
            "flagged": [0],
        },
        # Corporate download page whose tracking link only mentions a file-sharing site in its query string.
        "negative": {
            "rows": [download(source_url="https://files.example.com/get?id=42&src=dropbox.com", tab_url="https://intranet.example.com/redirect?to=wetransfer.com")],
            "flagged": [],
        },
    },
    "browser.dl_dangerous": {
        "positive": {
            "rows": [
                download(danger_type=1, danger_type_name="DANGEROUS_FILE", target_path=r"C:\Users\alice\Downloads\setup.exe"),
                # Weak verdict, but on an executable target.
                download(danger_type=4, danger_type_name="MAYBE_DANGEROUS_CONTENT", target_path=r"C:\Users\alice\Downloads\viewer_setup.msi"),
                # Numeric value only (no name column): 8 = POTENTIALLY_UNWANTED.
                download(danger_type=8, danger_type_name="", target_path=r"C:\Users\alice\Downloads\toolbar.zip"),
            ],
            "flagged": [0, 1, 2],
        },
        # Chrome marks ordinary uncommon documents MAYBE_DANGEROUS_CONTENT; a deep scan that found the file clean.
        "negative": {
            "rows": [
                download(danger_type=4, danger_type_name="MAYBE_DANGEROUS_CONTENT", source_url="https://www.example.go.kr/notice/form.hwp", target_path=r"C:\Users\alice\Downloads\form.hwp"),
                download(danger_type=5, danger_type_name="UNCOMMON_CONTENT", target_path=r"C:\Users\alice\Downloads\statement_2024.pdf"),
                download(danger_type=15, danger_type_name="DEEP_SCANNED_SAFE", target_path=r"C:\Users\alice\Downloads\setup.exe"),
            ],
            "flagged": [],
        },
    },
    "browser.dl_missing_file": {
        "positive": {
            "rows": [listed(r"C:\Users\alice\Downloads\other.pdf"), download(target_path=r"C:\Users\alice\Downloads\tool.zip")],
            "flagged": [1],
        },
        # The downloaded file is still in the listing.
        "negative": {
            "rows": [listed(r"C:\Users\alice\Downloads\other.pdf"), listed(r"C:\Users\alice\Downloads\report.pdf"), download()],
            "flagged": [],
        },
    },
    "browser.incognito_gap": {
        "positive": {
            "rows": [
                visit("2024-05-01T09:30:00Z"),
                prefetch_activity(["2024-05-02", "2024-05-03", "2024-05-04"]),
                visit("2024-05-05T18:00:00Z"),
            ],
            "flagged": [2],
        },
        # Holiday: no browsing and no other activity on the machine either.
        "negative": {
            "rows": [
                visit("2024-05-01T09:30:00Z"),
                prefetch_activity(["2024-05-01", "2024-05-05"]),
                visit("2024-05-05T18:00:00Z"),
            ],
            "flagged": [],
        },
    },
    "browser.history_cleared": {
        "positive": {"rows": [history(15231), history(15230), history(15400)], "flagged": [1]},
        # Long-used profile that still holds its early rows.
        "negative": {"rows": [history(15230), history(3), history(15400)], "flagged": []},
    },
    "browser.ext_broad_perm": {
        "positive": {"rows": [extension(permissions=["storage", "webRequest", "webRequestBlocking", "<all_urls>"])], "flagged": [0]},
        # MV3 content blocker: all-site access but declarativeNetRequest instead of webRequest.
        "negative": {"rows": [extension(name="Sample Blocker", permissions=["storage", "declarativeNetRequest"], host_permissions=["<all_urls>"])], "flagged": []},
    },
    "browser.ext_sideloaded": {
        "positive": {"rows": [extension(from_webstore=False, location_name="UNPACKED")], "flagged": [0]},
        # Browser component extension (not from the store, but shipped with the browser).
        "negative": {"rows": [extension(name="Sample Viewer", from_webstore=False, location_name="COMPONENT")], "flagged": []},
    },
    "browser.search_sensitive": {
        "positive": {"rows": [browser_row("browser-search", term="ssd 영구 삭제 프로그램", timestamp="2024-05-01T10:00:00Z")], "flagged": [0]},
        # Data-recovery search: mentions deletion but not a destruction keyword.
        "negative": {"rows": [browser_row("browser-search", term="삭제된 사진 복구 방법", timestamp="2024-05-01T10:00:00Z")], "flagged": []},
    },
    "browser.cred_first_use_new_site": {
        "positive": {
            "rows": [browser_row("browser-login", "Login Data", origin="https://portal.example.net/", date_created="2024-05-02T08:00:00Z")],
            "flagged": [0],
            "incident": ("2024-05-01T00:00:00Z", "2024-05-03T00:00:00Z"),
        },
        "negative": {
            "rows": [browser_row("browser-login", "Login Data", origin="https://portal.example.net/", date_created="2023-11-20T08:00:00Z")],
            "flagged": [],
            "incident": ("2024-05-01T00:00:00Z", "2024-05-03T00:00:00Z"),
        },
    },
    "browser.typed_url_direct": {
        "positive": {
            "rows": [visit("2024-05-01T10:00:00Z", "https://mega.nz/folder/XyZ123", transition=805306369, transition_core="TYPED")],
            "flagged": [0],
        },
        # Same site opened from a bookmark.
        "negative": {
            "rows": [visit("2024-05-01T10:00:00Z", "https://mega.nz/folder/XyZ123", transition=805306371, transition_core="AUTO_BOOKMARK")],
            "flagged": [],
        },
    },
    "browser.webmail_upload": {
        "positive": {
            "rows": [
                # POST cache entry to the Naver Mail attachment path (heuristic weak, raised to medium by the POST).
                pattern_candidate("https://mail.naver.com/json/write/upload/attach", "POST"),
                # Outlook web CreateAttachment action from history (documented endpoint: strong).
                pattern_candidate("https://outlook.office.com/owa/service.svc?action=CreateAttachmentFromLocalFile", source_artifact_type="browser-visit"),
                # Any POST to a webmail host is a candidate of its own (catalog rationale).
                pattern_candidate("https://mail.daum.net/hanmailex/compose/send.json", "POST"),
                # A file-sharing upload is the other rule's row.
                pattern_candidate("https://wetransfer.com/api/v4/transfers/link"),
            ],
            "flagged": [0, 1, 2],
        },
        # Weak tier the scanner really produces: Gmail attachment reference (attid) — opening an
        # attachment looks the same — and a GET of the Naver Mail upload path (page view, no POST).
        "negative": {
            "rows": [
                pattern_candidate("https://mail.google.com/mail/u/0/?ui=2&ik=abc&attid=0.1&disp=safe", source_artifact_type="browser-visit"),
                pattern_candidate("https://mail.naver.com/write/bigfile/upload", source_artifact_type="browser-history"),
            ],
            "flagged": [],
        },
    },
    "browser.filesharing_upload": {
        "positive": {
            "rows": [
                pattern_candidate("https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable", "POST"),
                pattern_candidate("https://wetransfer.com/api/v4/transfers/link"),
                pattern_candidate("https://mail.naver.com/json/write/upload/attach", "POST"),
                # POST to a web-hard host (label token match).
                pattern_candidate("https://www.webhard.co.kr/pages/fileup.php", "POST"),
            ],
            "flagged": [0, 1, 3],
        },
        # Weak tier the scanner really produces: GETs of upload screens (MYBOX, web-hard, MEGA, Send
        # Anywhere) — a page view, not a transfer — are candidates but not flagged at medium.
        "negative": {
            "rows": [
                pattern_candidate("https://mybox.naver.com/upload", source_artifact_type="browser-history"),
                pattern_candidate("https://www.webhard.co.kr/pages/fileup.php", source_artifact_type="browser-visit"),
                pattern_candidate("https://mega.nz/upload/folder"),
                pattern_candidate("https://send-anywhere.com/web/upload"),
            ],
            "flagged": [],
        },
    },
}
