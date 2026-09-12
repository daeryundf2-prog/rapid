from __future__ import annotations
import contextlib
import csv
import datetime as dt
import hashlib
import json
import plistlib
import shlex
import sqlite3
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from ...core.forensic_accuracy import build_accuracy_gate
from ...core.models import ArtifactRecord
from ...core.submission import compute_hashes
from ..review import build_forensic_review

from .helpers import (
    normalized_mobile_diff_value,
)
from .detect import (
    first_mobile_alias,
)


def index_mobile_trusted_rows(rows: list[Mapping[str, object]]) -> dict[str, dict[str, str]]:
    indexed: dict[str, dict[str, str]] = {}
    for row in rows:
        event_type = normalized_mobile_diff_value(first_mobile_alias(row, "artifact_type", "event_type", "type"))
        source_record_id_value = normalized_mobile_diff_value(first_mobile_alias(row, "source_record_id", "record_id", "id"))
        timestamp = normalized_mobile_diff_value(first_mobile_alias(row, "timestamp", "date", "time"))
        message_id = normalized_mobile_diff_value(first_mobile_alias(row, "message_id", "guid", "msg_id"))
        text_hash = normalized_mobile_diff_value(first_mobile_alias(row, "message_text_sha256", "text_sha256", "body_sha256"))
        sender = normalized_mobile_diff_value(first_mobile_alias(row, "sender", "from"))
        recipient = normalized_mobile_diff_value(first_mobile_alias(row, "recipient", "to"))
        domain = normalized_mobile_diff_value(first_mobile_alias(row, "domain"))
        file_id = normalized_mobile_diff_value(first_mobile_alias(row, "file_id", "fileID"))
        logical_path = normalized_mobile_diff_value(first_mobile_alias(row, "logical_path", "relative_path", "path"))
        table = normalized_mobile_diff_value(first_mobile_alias(row, "table", "table_name"))
        row_count = normalized_mobile_diff_value(first_mobile_alias(row, "row_count", "count"))
        key = "|".join(
            item
            for item in (
                event_type,
                source_record_id_value,
                message_id,
                timestamp,
                sender,
                recipient,
                domain,
                file_id,
                logical_path,
                table,
            )
            if item
        )
        if not key:
            continue
        indexed[key] = {
            "event_type": event_type,
            "source_record_id": source_record_id_value,
            "timestamp": timestamp,
            "message_id": message_id,
            "message_text_sha256": text_hash,
            "sender": sender,
            "recipient": recipient,
            "domain": domain,
            "file_id": file_id,
            "logical_path": logical_path,
            "table": table,
            "row_count": row_count,
        }
    return indexed
