from __future__ import annotations

from pathlib import Path
from xml.etree import ElementTree as ET


class UnsafeXmlError(ValueError):
    """Raised when XML contains constructs RapidTriage does not parse."""


def reject_unsafe_xml_constructs(xml_data: bytes | str) -> None:
    # Scan the whole document: stdlib ElementTree expands internal entities, so
    # a DTD beyond a fixed prefix window would still expose entity-expansion
    # (billion-laughs) denial of service on hostile evidence XML.
    if isinstance(xml_data, str):
        probe = xml_data.lower()
    else:
        probe = xml_data.lower().decode("utf-8", errors="ignore")
    if "<!doctype" in probe or "<!entity" in probe:
        raise UnsafeXmlError("XML DTD/entity declarations are disabled")


def safe_xml_fromstring(xml_data: bytes | str) -> ET.Element:
    reject_unsafe_xml_constructs(xml_data)
    return ET.fromstring(xml_data)


def safe_xml_parse(source: str | Path) -> ET.ElementTree:
    """Parse an XML file after rejecting DTD/entity declarations."""
    data = Path(source).read_bytes()
    reject_unsafe_xml_constructs(data)
    return ET.ElementTree(ET.fromstring(data))
