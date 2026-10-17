"""Fixtures of ``rapidtriage.core.triage_rules.messenger`` (see ``tests.triage_cases``)."""

from __future__ import annotations

import datetime as dt

KAKAO_DB = "C:\\Users\\analyst\\AppData\\Local\\Kakao\\KakaoTalk\\users\\example\\chat_data\\chatLogs_1.edb"
SMS_DB = "mobile-export\\sms.db"


def kakao(message_id: int, timestamp: str, conversation_id: str = "room-1", **details: object) -> dict[str, object]:
    return {
        "kind": "kakaotalk-windows",
        "row": {
            "artifact_type": "kakaotalk-message",
            "path": KAKAO_DB,
            "details": {"source_path": KAKAO_DB, "message_id": message_id, "conversation_id": conversation_id, "timestamp": timestamp, **details},
        },
    }


def sms(timestamp: str, **details: object) -> dict[str, object]:
    return {
        "kind": "mobile-export",
        "row": {"artifact_type": "mobile-message", "path": SMS_DB, "details": {"source_path": SMS_DB, "timestamp": timestamp, **details}},
    }


def listed(path: str) -> dict[str, object]:
    return {"files": "inventory", "row": {"path": path, "name": path.rsplit("\\", 1)[-1]}}


def series(start: str, count: int, step_minutes: float, **details: object) -> list[dict[str, object]]:
    first = dt.datetime.fromisoformat(start.replace("Z", "+00:00"))
    return [
        sms((first + dt.timedelta(minutes=step_minutes * index)).isoformat().replace("+00:00", "Z"), message_id=index + 1, **details)
        for index in range(count)
    ]


DOWNLOADS = "C:\\Users\\analyst\\Documents\\KakaoTalk Downloads"

CASES = {
    "messenger.time_regression": {
        "positive": {
            "rows": [
                kakao(1, "2024-03-01T10:00:00Z"),
                kakao(2, "2024-03-01T10:05:00Z"),
                kakao(3, "2024-03-01T09:00:00Z"),
            ],
            "flagged": [2],
        },
        "negative": {
            "rows": [
                kakao(1, "2024-03-01T10:00:00Z"),
                kakao(2, "2024-03-01T10:05:00Z"),
                # Resent after an offline queue: 30 s earlier than its predecessor (tolerance 60 s).
                kakao(3, "2024-03-01T10:04:30Z"),
                # Another room interleaves earlier times: separate conversation.
                kakao(4, "2024-03-01T09:00:00Z", conversation_id="room-2"),
            ],
            "flagged": [],
        },
    },
    "messenger.server_client_skew": {
        "positive": {"rows": [kakao(1, "2024-03-01T10:20:00Z", server_timestamp="2024-03-01T10:00:00Z")], "flagged": [0]},
        # Export with consistent clocks: two minutes of delivery delay.
        "negative": {"rows": [kakao(1, "2024-03-01T10:02:00Z", server_timestamp="2024-03-01T10:00:00Z")], "flagged": []},
    },
    "messenger.id_gap": {
        "positive": {
            "rows": [
                kakao(1, "2024-03-01T10:00:00Z"),
                kakao(2, "2024-03-01T10:01:00Z"),
                kakao(3, "2024-03-01T10:02:00Z"),
                kakao(4, "2024-03-01T10:03:00Z"),
                kakao(7, "2024-03-01T10:06:00Z"),
            ],
            "flagged": [4],
        },
        # Ids drawn from a global counter shared by every room: gaps are normal.
        "negative": {
            "rows": [
                kakao(100, "2024-03-01T10:00:00Z"),
                kakao(250, "2024-03-01T10:01:00Z"),
                kakao(380, "2024-03-01T10:02:00Z"),
                kakao(512, "2024-03-01T10:03:00Z"),
            ],
            "flagged": [],
        },
    },
    "messenger.deleted_recovered": {
        "positive": {
            "rows": [kakao(1, "2024-03-01T10:00:00Z", deleted_state="freelist"), sms("2024-03-01T10:00:00Z", wal_origin=True)],
            "flagged": [0, 1],
        },
        "negative": {
            "rows": [kakao(1, "2024-03-01T10:00:00Z", deleted_state="live"), sms("2024-03-01T10:00:00Z", is_deleted=False)],
            "flagged": [],
        },
    },
    "messenger.disappearing_on": {
        "positive": {"rows": [sms("2024-03-01T10:00:00Z", expire_timer=86400, conversation_id="thread-9")], "flagged": [0]},
        # Timer field present but off.
        "negative": {"rows": [sms("2024-03-01T10:00:00Z", expire_timer=0, conversation_id="thread-9")], "flagged": []},
    },
    "messenger.external_share_link": {
        "positive": {
            "rows": [
                kakao(1, "2024-03-01T10:00:00Z", message_text="자료 여기 https://mega.nz/file/AbCdEf#key"),
                kakao(2, "2024-03-01T10:01:00Z", message_text="링크 https://bit.ly/3xYzAbc"),
            ],
            "flagged": [0, 1],
        },
        # Ordinary link sharing and a look-alike host that is not a share service.
        "negative": {
            "rows": [
                kakao(1, "2024-03-01T10:00:00Z", message_text="뉴스 https://news.example.com/article/123"),
                kakao(2, "2024-03-01T10:01:00Z", message_text="https://notmega.nz/menu 점심 메뉴"),
            ],
            "flagged": [],
        },
    },
    "messenger.late_night_burst": {
        # Ten outgoing messages between 02:00 and 02:18 KST.
        "positive": {"rows": series("2024-03-01T17:00:00Z", 10, 2, direction="outgoing"), "flagged": list(range(10))},
        # A group-chat flood received at the same hour (incoming) is not the user's activity.
        "negative": {"rows": series("2024-03-01T17:00:00Z", 10, 2, direction="incoming"), "flagged": []},
    },
    "messenger.attachment_missing": {
        "positive": {
            "rows": [
                kakao(1, "2024-03-01T10:00:00Z", attachment_name="contract_draft.pdf"),
                listed(f"{DOWNLOADS}\\menu.jpg"),
            ],
            "flagged": [0],
        },
        # The attachment was downloaded and is in the listing.
        "negative": {
            "rows": [
                kakao(1, "2024-03-01T10:00:00Z", attachment_name="contract_draft.pdf"),
                listed(f"{DOWNLOADS}\\contract_draft.pdf"),
            ],
            "flagged": [],
        },
    },
    "messenger.app_reinstall_gap": {
        "positive": {
            "rows": [kakao(1, "2023-01-01T10:00:00Z"), kakao(2, "2023-01-02T10:00:00Z"), kakao(3, "2023-06-01T10:00:00Z")],
            "flagged": [2],
        },
        # Regular use with month-long pauses only.
        "negative": {
            "rows": [kakao(1, "2023-01-01T10:00:00Z"), kakao(2, "2023-02-15T10:00:00Z"), kakao(3, "2023-04-20T10:00:00Z")],
            "flagged": [],
        },
    },
}
