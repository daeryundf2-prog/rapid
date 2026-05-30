from __future__ import annotations

from xml.etree import ElementTree as ET


class UnsafeXmlError(ValueError):
    """Raised when XML contains constructs RapidTriage does not parse."""


def reject_unsafe_xml_constructs(xml_data: bytes | str) -> None:
    if isinstance(xml_data, str):
        probe = xml_data[:4096].lower()
    else:
        probe = xml_data[:4096].lower().decode("utf-8", errors="ignore")
    if "<!doctype" in probe or "<!entity" in probe:
        raise UnsafeXmlError("XML DTD/entity declarations are disabled")


def safe_xml_fromstring(xml_data: bytes | str) -> ET.Element:
    reject_unsafe_xml_constructs(xml_data)
    return ET.fromstring(xml_data)
