"""Map-URL location candidates from browser rows (R5 L3; 재감사 §3 item 4).

:class:`LocationUrlScanner` watches the rows the browser provider emits (``browser-history``,
``browser-visit``, ``browser-bookmark``) and turns every Google Maps / Naver Map / Kakao Map
URL that names a coordinate, a search text or a route (``core.derived.map_urls``) into one
``location-url-candidate`` row: ``latitude`` / ``longitude`` (read by the R4 지도 대체 보기 and
the server ``geo=`` filter), ``query``, ``origin`` / ``destination``, the visit time and the
source row's type / path / row id. A row is a lead: the coordinate is the URL's map centre or
pin, not where the device was.

Rows are de-duplicated on (browser, profile, URL, time): a URL row's last-visit time equals its
last visit row, so the two produce one candidate.
"""

from __future__ import annotations

from ...core.models import ArtifactRecord
from ..url_redaction import redact_url_fields

LOCATION_SOURCE_TYPES = frozenset({"browser-history", "browser-visit", "browser-bookmark"})
MAX_LOCATION_CANDIDATES = 50_000
LOCATION_INTERPRETATION = (
    "지도 URL이 가리킨 위치·검색어·경로(후보). 좌표는 지도 화면 중심이나 URL이 가리킨 장소이며 기기의 위치가 아님"
)


class LocationUrlScanner:
    """Collects ``location-url-candidate`` rows while the browser provider streams its rows."""

    def __init__(self) -> None:
        # Imported here: ``core.derived`` loads the triage engine, which imports the artifact providers.
        from ...core.derived.map_urls import maybe_map_url, parse_map_url

        self.maybe_map_url = maybe_map_url
        self.parse_map_url = parse_map_url
        self.candidates: list[ArtifactRecord] = []
        self.seen: set[tuple[str, str, str, str]] = set()
        self.capped = False

    def observe(self, record: ArtifactRecord) -> None:
        if record.artifact_type not in LOCATION_SOURCE_TYPES:
            return
        details = record.details
        url = str(details.get("url") or "")
        if not url or not self.maybe_map_url(url):
            return
        parsed = self.parse_map_url(url)
        if parsed is None:
            return
        timestamp = details.get("timestamp")
        key = (str(details.get("browser") or ""), str(details.get("profile") or ""), url, str(timestamp or ""))
        if key in self.seen:
            return
        if len(self.candidates) >= MAX_LOCATION_CANDIDATES:
            self.capped = True
            return
        self.seen.add(key)
        self.candidates.append(build_location_candidate(record, parsed))


def build_location_candidate(record: ArtifactRecord, parsed: dict[str, object]) -> ArtifactRecord:
    from ...core.derived.map_urls import MAP_URL_PARSER, MAP_URL_PARSER_VERSION

    details = record.details
    fields: dict[str, object] = {
        "parser": MAP_URL_PARSER,
        "parser_version": MAP_URL_PARSER_VERSION,
        "coverage_status": "derived-candidate",
        "recovery_method": "derived",
        "user": details.get("user", ""),
        "browser": details.get("browser", ""),
        "profile": details.get("profile", ""),
        "timestamp": details.get("timestamp"),
        "timestamp_kind": details.get("timestamp_kind", ""),
        "timestamp_timezone": details.get("timestamp_timezone", ""),
        "url": str(details.get("url") or ""),
        "title": str(details.get("title") or "")[:300],
        **parsed,
        "source_artifact_type": record.artifact_type,
        "source_path": details.get("source_path") or record.path,
        "source_table": details.get("source_table", ""),
        "source_row_id": details.get("source_row_id"),
        "interpretation_ko": LOCATION_INTERPRETATION,
    }
    # The source row is read before the upload scanner redacts it: redact token-bearing query values here too.
    redact_url_fields(fields, ("url",))
    return ArtifactRecord(
        provider=record.provider, artifact_type="location-url-candidate", path=record.path, supported=True, details=fields
    )
