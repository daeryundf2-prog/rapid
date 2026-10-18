"""Map URLs -> location candidates (R5 L3; 재감사 §3 item 4).

:func:`parse_map_url` reads a visited map URL and returns what the URL itself says --
coordinates, a search text, a route's origin / destination -- never what the page showed:

* Google Maps (``google.<tld>/maps``, ``maps.google.<tld>``): ``/maps/place/<name>``,
  ``/maps/search/<q>``, ``/maps/dir/<a>/<b>/…``, the viewport ``/@lat,lng,zoomz`` and the
  place pin ``!3d<lat>!4d<lng>`` of the ``data=`` segment (the pin wins over the viewport),
  ``q=`` / ``query=`` / ``ll=`` / ``saddr=`` / ``daddr=`` / ``origin=`` / ``destination=``;
* Naver Map (``map.naver.com``, ``m.map.naver.com``): ``c=x,y,zoom,…`` in Web Mercator metres
  (EPSG:3857, converted to WGS84) or in degrees, ``lng=`` / ``lat=``, ``/search/<q>``,
  ``/directions/<x,y,name,…>/<x,y,name,…>``, ``query=``;
* Kakao Map (``map.kakao.com``): ``/link/map|to|from/<name>,<lat>,<lng>``,
  ``/link/roadview/<lat>,<lng>``, ``/link/search/<q>``, ``q=``. ``urlX`` / ``urlY`` are
  Kakao's WCONGNAMUL plane coordinates; they are kept as text, not converted.

The coordinate is a *URL* coordinate: the map's viewport centre or the pin the URL names,
not the device's position (``coordinate_basis`` says which).
"""

from __future__ import annotations

import math
import re
from urllib.parse import parse_qs, unquote_plus, urlsplit

MAP_URL_PARSER = "map-url-location"
MAP_URL_PARSER_VERSION = "map-url-location-v1"
MAX_URL_CHARS = 8192
MAX_TEXT_CHARS = 300
EARTH_RADIUS_M = 6378137.0
GOOGLE_HOST = re.compile(r"^(?:www\.|maps\.)?google\.(?:[a-z]{2,3}|co\.[a-z]{2}|com\.[a-z]{2})$")
GOOGLE_VIEWPORT = re.compile(r"@(-?\d{1,3}(?:\.\d+)?),(-?\d{1,3}(?:\.\d+)?)(?:,(\d{1,2}(?:\.\d+)?)z)?")
GOOGLE_PIN = re.compile(r"!3d(-?\d{1,3}(?:\.\d+)?)!4d(-?\d{1,3}(?:\.\d+)?)")
LAT_LNG = re.compile(r"^\s*(-?\d{1,3}(?:\.\d+)?)\s*,\s*(-?\d{1,3}(?:\.\d+)?)\s*$")
NUMBER = re.compile(r"^-?\d+(?:\.\d+)?$")
PROVIDER_LABELS = {"google-maps": "Google 지도", "naver-map": "네이버 지도", "kakao-map": "카카오맵"}
KIND_LABELS = {
    "place": "장소",
    "search": "검색",
    "directions": "길찾기",
    "coordinates": "좌표",
    "roadview": "로드뷰",
}


def map_provider(host: str) -> str | None:
    host = host.lower().strip(".")
    if GOOGLE_HOST.fullmatch(host):
        return "google-maps"
    if host in ("map.naver.com", "m.map.naver.com", "v4.map.naver.com"):
        return "naver-map"
    if host in ("map.kakao.com", "m.map.kakao.com"):
        return "kakao-map"
    return None


def web_mercator_to_wgs84(x: float, y: float) -> tuple[float, float]:
    """``(lat, lon)`` of an EPSG:3857 point (metres)."""
    lon = math.degrees(x / EARTH_RADIUS_M)
    lat = math.degrees(2.0 * math.atan(math.exp(y / EARTH_RADIUS_M)) - math.pi / 2.0)
    return lat, lon


def _valid(lat: float, lon: float) -> bool:
    return -90.0 <= lat <= 90.0 and -180.0 <= lon <= 180.0 and not (lat == 0.0 and lon == 0.0)


def _text(value: str) -> str:
    return " ".join(unquote_plus(value).split())[:MAX_TEXT_CHARS]


def _first(query: dict[str, list[str]], *names: str) -> str:
    for name in names:
        values = query.get(name)
        if values and values[0].strip():
            return values[0]
    return ""


def _lat_lng(text: str) -> tuple[float, float] | None:
    match = LAT_LNG.fullmatch(unquote_plus(text))
    if not match:
        return None
    lat, lon = float(match.group(1)), float(match.group(2))
    return (lat, lon) if _valid(lat, lon) else None


def _segments(path: str) -> list[str]:
    return [segment for segment in path.split("/") if segment]


def _result(provider: str, kind: str) -> dict[str, object]:
    return {
        "map_provider": provider,
        "map_provider_label": PROVIDER_LABELS[provider],
        "map_url_kind": kind,
        "map_url_kind_label": KIND_LABELS[kind],
        "latitude": None,
        "longitude": None,
        "zoom": None,
        "coordinate_basis": "",
        "query": "",
        "origin": "",
        "destination": "",
        "waypoints": [],
    }


def _set_point(result: dict[str, object], lat: float, lon: float, basis: str) -> None:
    if _valid(lat, lon):
        result["latitude"] = round(lat, 7)
        result["longitude"] = round(lon, 7)
        result["coordinate_basis"] = basis


def _google(path: str, query: dict[str, list[str]], full: str) -> dict[str, object] | None:
    segments = _segments(path)
    if segments[:1] != ["maps"] and not query:
        return None
    rest = segments[1:] if segments[:1] == ["maps"] else segments
    kind = "coordinates"
    result = _result("google-maps", kind)
    head = rest[0] if rest else ""
    if head == "place" and len(rest) > 1 and not rest[1].startswith("@"):
        kind = "place"
        result["query"] = _text(rest[1])
    elif head == "search" and len(rest) > 1 and not rest[1].startswith("@"):
        kind = "search"
        result["query"] = _text(rest[1])
    elif head == "dir":
        kind = "directions"
        stops = [_text(item) for item in rest[1:] if not item.startswith("@") and not item.startswith("data=")]
        stops = [stop for stop in stops if stop]
        if stops:
            result["origin"] = stops[0]
        if len(stops) > 1:
            result["destination"] = stops[-1]
            result["waypoints"] = stops[1:-1][:10]
    api_query = _first(query, "q", "query")
    if api_query and not result["query"]:
        result["query"] = _text(api_query)
        if kind == "coordinates":
            kind = "search"
    origin = _first(query, "saddr", "origin")
    destination = _first(query, "daddr", "destination")
    if origin or destination:
        kind = "directions"
        result["origin"] = result["origin"] or _text(origin)
        result["destination"] = result["destination"] or _text(destination)
    pin = GOOGLE_PIN.search(full)
    viewport = GOOGLE_VIEWPORT.search(path)
    if pin:
        _set_point(result, float(pin.group(1)), float(pin.group(2)), "url-place-pin")
    elif viewport:
        _set_point(result, float(viewport.group(1)), float(viewport.group(2)), "url-viewport-center")
    else:
        for name, basis in (("ll", "url-ll-parameter"), ("q", "url-query-coordinates"), ("query", "url-query-coordinates")):
            point = _lat_lng(_first(query, name))
            if point:
                _set_point(result, point[0], point[1], basis)
                break
    if viewport and viewport.group(3):
        result["zoom"] = float(viewport.group(3))
    result["map_url_kind"] = kind
    result["map_url_kind_label"] = KIND_LABELS[kind]
    return result if _meaningful(result) else None


def _naver_point(x_text: str, y_text: str) -> tuple[float, float, str] | None:
    """``(lat, lon, basis)`` of a Naver ``x,y`` pair (EPSG:3857 metres, or degrees)."""
    if not NUMBER.fullmatch(x_text) or not NUMBER.fullmatch(y_text):
        return None
    x, y = float(x_text), float(y_text)
    if x == 0.0 or y == 0.0:
        return None  # zoom-only ``c=15.00,0,0,0,dh`` (new Naver Map) carries no position
    if abs(x) <= 180.0 and abs(y) <= 90.0:
        return (y, x, "url-wgs84") if _valid(y, x) else None
    if abs(x) > 20037508.35 or abs(y) > 20048966.11:
        return None
    lat, lon = web_mercator_to_wgs84(x, y)
    return (lat, lon, "url-epsg3857-converted") if _valid(lat, lon) else None


def _naver(path: str, query: dict[str, list[str]]) -> dict[str, object] | None:
    segments = _segments(path)
    kind = "coordinates"
    result = _result("naver-map", kind)
    for index, segment in enumerate(segments):
        if segment in ("search", "search2") and index + 1 < len(segments):
            candidate = segments[index + 1]
            if not candidate.endswith(".naver"):
                kind = "search"
                result["query"] = _text(candidate)
            break
        if segment == "directions":
            kind = "directions"
            stops = []
            for item in segments[index + 1 : index + 6]:
                parts = unquote_plus(item).split(",")
                if len(parts) >= 3 and NUMBER.fullmatch(parts[0]):
                    stops.append(" ".join(parts[2].split())[:MAX_TEXT_CHARS] or f"{parts[0]},{parts[1]}")
            if stops:
                result["origin"] = stops[0]
            if len(stops) > 1:
                result["destination"] = stops[-1]
            break
        if segment == "place" and index + 1 < len(segments):
            kind = "place"
            result["query"] = _text(segments[index + 1])
    text_query = _first(query, "query", "q")
    if text_query and not result["query"]:
        result["query"] = _text(text_query)
        kind = "search" if kind == "coordinates" else kind
    c_value = _first(query, "c")
    point = None
    if c_value:
        parts = unquote_plus(c_value).split(",")
        if len(parts) >= 2:
            point = _naver_point(parts[0].strip(), parts[1].strip())
            if point and len(parts) >= 3 and NUMBER.fullmatch(parts[2].strip()):
                result["zoom"] = float(parts[2])
    if point is None:
        lng, lat = _first(query, "lng", "x"), _first(query, "lat", "y")
        if lng and lat:
            point = _naver_point(lng.strip(), lat.strip())
    if point is not None:
        _set_point(result, point[0], point[1], point[2])
    result["map_url_kind"] = kind
    result["map_url_kind_label"] = KIND_LABELS[kind]
    return result if _meaningful(result) else None


def _kakao(path: str, query: dict[str, list[str]]) -> dict[str, object] | None:
    segments = _segments(path)
    kind = "coordinates"
    result = _result("kakao-map", kind)
    if segments[:1] == ["link"] and len(segments) >= 3:
        action, value = segments[1], unquote_plus("/".join(segments[2:]))
        parts = [part.strip() for part in value.split(",")]
        if action == "search":
            kind = "search"
            result["query"] = _text(value)
        elif action == "roadview" and len(parts) >= 2 and NUMBER.fullmatch(parts[0]) and NUMBER.fullmatch(parts[1]):
            kind = "roadview"
            _set_point(result, float(parts[0]), float(parts[1]), "url-link-coordinates")
        elif action in ("map", "to", "from"):
            kind = "directions" if action in ("to", "from") else "place"
            name = " ".join(parts[0].split())[:MAX_TEXT_CHARS] if parts else ""
            if len(parts) >= 3 and NUMBER.fullmatch(parts[-2]) and NUMBER.fullmatch(parts[-1]):
                name = " ".join(",".join(parts[:-2]).split())[:MAX_TEXT_CHARS]
                _set_point(result, float(parts[-2]), float(parts[-1]), "url-link-coordinates")
            if action == "to":
                result["destination"] = name
            elif action == "from":
                result["origin"] = name
            else:
                result["query"] = name
    text_query = _first(query, "q", "query")
    if text_query and not result["query"]:
        result["query"] = _text(text_query)
        kind = "search" if kind == "coordinates" else kind
    url_x, url_y = _first(query, "urlX"), _first(query, "urlY")
    if url_x and url_y and result["latitude"] is None:
        result["plane_coordinates"] = f"{url_x[:20]},{url_y[:20]}"
        result["plane_coordinate_system"] = "WCONGNAMUL(카카오 평면 좌표, 변환하지 않음)"
    result["map_url_kind"] = kind
    result["map_url_kind_label"] = KIND_LABELS[kind]
    return result if _meaningful(result) or result.get("plane_coordinates") else None


def _meaningful(result: dict[str, object]) -> bool:
    return result["latitude"] is not None or any(result[key] for key in ("query", "origin", "destination"))


def parse_map_url(url: str) -> dict[str, object] | None:
    """Location fields of a map URL (see module doc), ``None`` when ``url`` is not one or says nothing."""
    if not url or len(url) > MAX_URL_CHARS:
        return None
    try:
        parts = urlsplit(url.strip())
        host = (parts.hostname or "").lower()
    except ValueError:
        return None
    if parts.scheme.lower() not in ("http", "https"):
        return None
    provider = map_provider(host)
    if provider is None:
        return None
    try:
        query = parse_qs(parts.query, keep_blank_values=False, max_num_fields=200)
    except ValueError:
        query = {}
    try:
        if provider == "google-maps":
            if not (host.startswith("maps.") or parts.path.startswith("/maps")):
                return None
            return _google(parts.path, query, url)
        if provider == "naver-map":
            return _naver(parts.path, query)
        return _kakao(parts.path, query)
    except (ValueError, OverflowError):
        return None


def maybe_map_url(url: str) -> bool:
    """Cheap pre-filter before :func:`parse_map_url` (a map host name is in the first 80 chars)."""
    head = url[:80].lower()
    return "map" in head and ("google." in head or "naver.com" in head or "kakao.com" in head)
