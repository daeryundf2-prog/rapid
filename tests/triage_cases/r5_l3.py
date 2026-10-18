"""Fixtures of the R5 L3 rules (``browser.torrent_site_visit``, ``p2p.torrent_seeding_uploaded``,
``p2p.transfer_completed``, ``p2p.emule_shared_uploaded``); see ``tests.triage_cases``."""

from __future__ import annotations


def visit(url: str) -> dict[str, object]:
    return {
        "kind": "windows-browser",
        "row": {
            "artifact_type": "browser-visit",
            "path": r"C:\Users\alice\AppData\Local\Google\Chrome\User Data\Default\History",
            "details": {"url": url, "visit_time": "2025-03-01T12:00:00Z"},
        },
    }


def transfer(name: str, *, client: str = "qbittorrent", uploaded: int = 0, state: str = "downloading", completed: str = "") -> dict[str, object]:
    details: dict[str, object] = {
        "client": client,
        "name": name,
        "uploaded_bytes": uploaded,
        "state": state,
        "info_hash": "0" * 40,
        "save_path": r"C:\Users\alice\Downloads",
    }
    if completed:
        details["completed_at"] = completed
    return {
        "kind": "p2p",
        "row": {"artifact_type": "p2p-transfer", "path": r"C:\Users\alice\AppData\Local\qBittorrent\BT_backup\x.fastresume", "details": details},
    }


def shared(name: str, *, uploaded: int = 0, accepted: int = 0) -> dict[str, object]:
    return {
        "kind": "p2p",
        "row": {
            "artifact_type": "p2p-shared-file",
            "path": r"C:\Users\alice\AppData\Local\eMule\config\known.met",
            "details": {"file_name": name, "all_time_uploaded_bytes": uploaded, "all_time_accepted": accepted, "ed2k_hash": "1" * 32},
        },
    }


CASES = {
    "browser.torrent_site_visit": {
        "positive": {
            "rows": [visit("https://thepiratebay.org/search.php?q=x"), visit("magnet:?xt=urn:btih:" + "a" * 40)],
            "flagged": [0, 1],
        },
        "negative": {"rows": [visit("https://www.example.com/torrent-guide")], "flagged": []},
    },
    "p2p.torrent_seeding_uploaded": {
        "positive": {"rows": [transfer("a.mp4", uploaded=4096)], "flagged": [0]},
        # Nothing sent to peers, and eMule rows are left to p2p.emule_shared_uploaded.
        "negative": {"rows": [transfer("a.mp4"), transfer("b.mp4", client="emule", uploaded=4096)], "flagged": []},
    },
    "p2p.transfer_completed": {
        "positive": {"rows": [transfer("a.mp4", state="completed", completed="2025-03-01T13:00:00Z")], "flagged": [0]},
        "negative": {"rows": [transfer("a.mp4", state="downloading", completed="")], "flagged": []},
    },
    "p2p.emule_shared_uploaded": {
        "positive": {"rows": [shared("a.avi", uploaded=1024), shared("b.avi", accepted=2)], "flagged": [0, 1]},
        "negative": {"rows": [shared("c.avi")], "flagged": []},
    },
}
