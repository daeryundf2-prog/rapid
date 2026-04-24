from __future__ import annotations

import importlib.metadata
import importlib.util
import os
import platform
import shutil
import socket
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional, Sequence


ToolResolver = Callable[[str], Optional[str]]

OK = "ok"
WARN = "warn"
ERROR = "error"


@dataclass(frozen=True)
class DoctorCheck:
    name: str
    category: str
    status: str
    summary: str
    details: dict[str, object]
    remediation: str | None = None

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "name": self.name,
            "category": self.category,
            "status": self.status,
            "summary": self.summary,
            "details": self.details,
        }
        if self.remediation:
            payload["remediation"] = self.remediation
        return payload


def default_app_data_dir() -> Path:
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA")
        if base:
            return Path(base) / "RapidTriage"
        return Path.home() / "AppData" / "Local" / "RapidTriage"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "RapidTriage"
    base = os.environ.get("XDG_DATA_HOME")
    if base:
        return Path(base) / "rapidtriage"
    return Path.home() / ".local" / "share" / "rapidtriage"


def run_doctor(
    *,
    host: str = "127.0.0.1",
    port: int = 8765,
    app_data_dir: Path | None = None,
    static_dir: Path | None = None,
    tool_resolver: ToolResolver = shutil.which,
    include_port_check: bool = True,
    write_probe: bool = True,
) -> dict[str, object]:
    static_root = static_dir or Path(__file__).resolve().parent.parent / "web" / "static"
    data_dir = app_data_dir or default_app_data_dir()
    checks = [
        check_python_version(),
        check_package_import("rapidtriage", "core", required=True),
        check_package_import("fastapi", "web", required=False, extra="web"),
        check_package_import("uvicorn", "web", required=False, extra="web"),
        check_static_assets(static_root),
        check_app_data_dir(data_dir, write_probe=write_probe),
        check_tesseract(tool_resolver),
        check_e01_tools(tool_resolver),
    ]
    if include_port_check:
        checks.append(check_port_available(host, port))

    counts = {OK: 0, WARN: 0, ERROR: 0}
    for check in checks:
        counts[check.status] = counts.get(check.status, 0) + 1
    overall_status = ERROR if counts[ERROR] else WARN if counts[WARN] else OK
    return {
        "command": "doctor",
        "status": overall_status,
        "summary": {
            "ok": counts[OK],
            "warn": counts[WARN],
            "error": counts[ERROR],
            "check_count": len(checks),
        },
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "python": sys.version.split()[0],
            "executable": sys.executable,
        },
        "paths": {
            "app_data_dir": str(data_dir.expanduser()),
            "static_dir": str(static_root),
        },
        "checks": [check.to_dict() for check in checks],
    }


def check_python_version() -> DoctorCheck:
    minimum = (3, 9)
    current = sys.version_info[:3]
    if current >= minimum:
        return DoctorCheck(
            name="python-version",
            category="core",
            status=OK,
            summary=f"Python {current[0]}.{current[1]}.{current[2]} is supported.",
            details={"minimum": "3.9", "current": ".".join(str(part) for part in current)},
        )
    return DoctorCheck(
        name="python-version",
        category="core",
        status=ERROR,
        summary=f"Python {current[0]}.{current[1]}.{current[2]} is too old.",
        details={"minimum": "3.9", "current": ".".join(str(part) for part in current)},
        remediation="Install Python 3.9 or newer.",
    )


def check_package_import(package: str, category: str, *, required: bool, extra: str | None = None) -> DoctorCheck:
    spec = importlib.util.find_spec(package)
    if spec is None:
        status = ERROR if required else WARN
        remediation = f"Install the '{extra}' extra: pip install 'dashcam-tools[{extra}]'." if extra else f"Install {package}."
        return DoctorCheck(
            name=f"python-package:{package}",
            category=category,
            status=status,
            summary=f"Python package '{package}' is not importable.",
            details={"package": package, "required": required, "extra": extra},
            remediation=remediation,
        )
    version = package_version(package)
    return DoctorCheck(
        name=f"python-package:{package}",
        category=category,
        status=OK,
        summary=f"Python package '{package}' is importable.",
        details={"package": package, "version": version, "origin": spec.origin},
    )


def package_version(package: str) -> str | None:
    candidates = [package, package.replace("_", "-")]
    if package == "rapidtriage":
        candidates.append("dashcam-tools")
    for candidate in candidates:
        try:
            return importlib.metadata.version(candidate)
        except importlib.metadata.PackageNotFoundError:
            continue
    return None


def check_static_assets(static_dir: Path) -> DoctorCheck:
    required = ("index.html", "app.js", "styles.css")
    missing = [name for name in required if not (static_dir / name).is_file()]
    if missing:
        return DoctorCheck(
            name="web-static-assets",
            category="web",
            status=ERROR,
            summary="Web UI static assets are incomplete.",
            details={"static_dir": str(static_dir), "missing": missing, "required": list(required)},
            remediation="Reinstall the package or rebuild the release artifact with rapidtriage/web/static included.",
        )
    return DoctorCheck(
        name="web-static-assets",
        category="web",
        status=OK,
        summary="Web UI static assets are present.",
        details={"static_dir": str(static_dir), "required": list(required)},
    )


def check_app_data_dir(app_data_dir: Path, *, write_probe: bool) -> DoctorCheck:
    target = app_data_dir.expanduser()
    details: dict[str, object] = {"path": str(target), "write_probe": write_probe}
    if not write_probe:
        return DoctorCheck(
            name="app-data-dir",
            category="storage",
            status=OK,
            summary="App data directory path resolved; write probe skipped.",
            details=details,
        )
    try:
        target.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(prefix="rapidtriage-doctor-", dir=target, delete=True) as handle:
            handle.write(b"ok")
            handle.flush()
        return DoctorCheck(
            name="app-data-dir",
            category="storage",
            status=OK,
            summary="App data directory is writable.",
            details=details,
        )
    except OSError as exc:
        details["error"] = str(exc)
        return DoctorCheck(
            name="app-data-dir",
            category="storage",
            status=ERROR,
            summary="App data directory is not writable.",
            details=details,
            remediation="Choose a writable case/app-data directory or fix filesystem permissions.",
        )


def check_tesseract(tool_resolver: ToolResolver) -> DoctorCheck:
    path = tool_resolver("tesseract")
    tessdata_prefix = os.environ.get("TESSDATA_PREFIX")
    details: dict[str, object] = {"path": path, "tessdata_prefix": tessdata_prefix}
    if path is None:
        return DoctorCheck(
            name="tool:tesseract",
            category="ocr",
            status=WARN,
            summary="Tesseract is not available; OCR will be disabled.",
            details=details,
            remediation="Install Tesseract OCR and ensure 'tesseract' is on PATH. On Windows, also verify tessdata language files.",
        )
    details["version"] = tool_version([path, "--version"])
    return DoctorCheck(
        name="tool:tesseract",
        category="ocr",
        status=OK,
        summary="Tesseract is available for OCR.",
        details=details,
    )


def check_e01_tools(tool_resolver: ToolResolver) -> DoctorCheck:
    tools = ("ewfmount", "mmls", "tsk_recover")
    resolved = {tool: tool_resolver(tool) for tool in tools}
    missing = [tool for tool, path in resolved.items() if path is None]
    details = {"tools": resolved, "missing": missing}
    if missing:
        return DoctorCheck(
            name="tools:e01",
            category="evidence-image",
            status=WARN,
            summary="E01 direct extraction tools are incomplete.",
            details=details,
            remediation="Install libewf and Sleuth Kit, use WSL2, or mount/extract the image first and scan the mounted folder.",
        )
    return DoctorCheck(
        name="tools:e01",
        category="evidence-image",
        status=OK,
        summary="E01 direct extraction tools are available.",
        details=details,
    )


def check_port_available(host: str, port: int) -> DoctorCheck:
    details: dict[str, object] = {"host": host, "port": port}
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((host, port))
        return DoctorCheck(
            name="web-port",
            category="web",
            status=OK,
            summary=f"Web port {host}:{port} is available.",
            details=details,
        )
    except OSError as exc:
        details["error"] = str(exc)
        return DoctorCheck(
            name="web-port",
            category="web",
            status=WARN,
            summary=f"Web port {host}:{port} is not available.",
            details=details,
            remediation="Stop the process using this port or start rapidtriage web with a different --port.",
        )


def tool_version(command: Sequence[str]) -> str | None:
    try:
        result = subprocess.run(list(command), capture_output=True, text=True, timeout=3)
    except (OSError, subprocess.TimeoutExpired):
        return None
    text = (result.stdout or result.stderr).strip()
    return text.splitlines()[0] if text else None


def format_doctor_text(payload: dict[str, object]) -> str:
    summary = payload["summary"]
    platform_info = payload["platform"]
    paths = payload["paths"]
    lines = [
        "rapidtriage doctor",
        f"Status: {payload['status']}",
        f"Checks: {summary['ok']} ok, {summary['warn']} warn, {summary['error']} error",
        f"Platform: {platform_info['system']} {platform_info['release']} ({platform_info['machine']})",
        f"Python: {platform_info['python']} at {platform_info['executable']}",
        f"App data: {paths['app_data_dir']}",
        f"Static assets: {paths['static_dir']}",
        "",
        "Checks:",
    ]
    for check in payload["checks"]:
        lines.append(f"- [{str(check['status']).upper()}] {check['name']}: {check['summary']}")
        remediation = check.get("remediation")
        if remediation:
            lines.append(f"  Fix: {remediation}")
    return "\n".join(lines)
