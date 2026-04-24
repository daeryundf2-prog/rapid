from __future__ import annotations

import datetime as dt
import json
import zipfile
from pathlib import Path
from typing import Mapping

from .case_db import normalize_identifier
from .search import load_run_summary


CATALOG_VERSION = 1


class CaseCatalogError(ValueError):
    """Raised when a case catalog operation is invalid."""


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


class CaseCatalog:
    def __init__(self, path: Path):
        self.path = path.expanduser().resolve()

    def load(self) -> dict[str, object]:
        if not self.path.is_file():
            return {"version": CATALOG_VERSION, "updated_at": now_iso(), "cases": []}
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise CaseCatalogError(f"could not read case catalog: {self.path}") from exc
        cases = payload.get("cases") if isinstance(payload, Mapping) else None
        if not isinstance(cases, list):
            raise CaseCatalogError("case catalog does not contain a cases list")
        return {"version": CATALOG_VERSION, "updated_at": str(payload.get("updated_at") or now_iso()), "cases": cases}

    def save(self, payload: Mapping[str, object]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        output = {
            "version": CATALOG_VERSION,
            "updated_at": now_iso(),
            "cases": payload.get("cases", []),
        }
        temporary_path = self.path.with_name(f"{self.path.name}.tmp")
        temporary_path.write_text(json.dumps(output, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        temporary_path.replace(self.path)

    def list_cases(self) -> list[dict[str, object]]:
        payload = self.load()
        return sorted(
            [case for case in payload["cases"] if isinstance(case, dict)],
            key=lambda item: str(item.get("updated_at") or ""),
            reverse=True,
        )

    def add_run(
        self,
        *,
        run_output: Path,
        case_id: str,
        name: str | None = None,
        description: str = "",
        examiner: str = "",
        organization: str = "",
    ) -> dict[str, object]:
        summary = load_run_summary(run_output)
        normalized_case_id = normalize_identifier(case_id, fallback="case")
        payload = self.load()
        cases = [case for case in payload["cases"] if isinstance(case, dict)]
        timestamp = now_iso()
        case = next((item for item in cases if item.get("case_id") == normalized_case_id), None)
        if case is None:
            case = {
                "case_id": normalized_case_id,
                "name": name or normalized_case_id,
                "description": description,
                "examiner": examiner,
                "organization": organization,
                "created_at": timestamp,
                "updated_at": timestamp,
                "runs": [],
                "evidence_sources": [],
            }
            cases.append(case)
        else:
            case["name"] = name or case.get("name") or normalized_case_id
            case["description"] = description or case.get("description", "")
            case["examiner"] = examiner or case.get("examiner", "")
            case["organization"] = organization or case.get("organization", "")
            case["updated_at"] = timestamp

        run_record = build_run_record(summary)
        runs = case.setdefault("runs", [])
        if not isinstance(runs, list):
            runs = []
            case["runs"] = runs
        runs[:] = [item for item in runs if not isinstance(item, dict) or item.get("summary_path") != run_record["summary_path"]]
        runs.append(run_record)

        evidence_sources = case.setdefault("evidence_sources", [])
        if isinstance(evidence_sources, list):
            source = summary.get("source") if isinstance(summary.get("source"), Mapping) else {}
            source_path = str(source.get("source_path") or summary.get("root") or "")
            if source_path and source_path not in [str(item.get("path")) for item in evidence_sources if isinstance(item, dict)]:
                evidence_sources.append({"path": source_path, "type": source.get("type") or summary.get("input_kind") or ""})

        self.save({"cases": cases})
        return case

    def export_case(self, *, case_id: str, output_zip: Path) -> dict[str, object]:
        normalized_case_id = normalize_identifier(case_id, fallback="case")
        case = next((item for item in self.list_cases() if item.get("case_id") == normalized_case_id), None)
        if case is None:
            raise CaseCatalogError(f"case not found: {normalized_case_id}")
        output_zip = output_zip.expanduser().resolve()
        output_zip.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(output_zip, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("case-catalog-entry.json", json.dumps(case, ensure_ascii=False, indent=2))
            for run in case.get("runs", []):
                if not isinstance(run, Mapping):
                    continue
                summary_path = Path(str(run.get("summary_path") or "")).expanduser()
                if summary_path.is_file():
                    archive.write(summary_path, f"runs/{summary_path.name}")
        return {"case_id": normalized_case_id, "archive": str(output_zip), "size": output_zip.stat().st_size}

    def import_archive(self, archive_path: Path) -> dict[str, object]:
        archive_path = archive_path.expanduser().resolve()
        if not archive_path.is_file():
            raise CaseCatalogError(f"archive not found: {archive_path}")
        with zipfile.ZipFile(archive_path) as archive:
            try:
                case = json.loads(archive.read("case-catalog-entry.json").decode("utf-8"))
            except (KeyError, json.JSONDecodeError) as exc:
                raise CaseCatalogError("archive does not contain a valid case-catalog-entry.json") from exc
        if not isinstance(case, dict) or not case.get("case_id"):
            raise CaseCatalogError("archive case entry is invalid")
        payload = self.load()
        cases = [item for item in payload["cases"] if isinstance(item, dict) and item.get("case_id") != case["case_id"]]
        case["imported_at"] = now_iso()
        case["updated_at"] = now_iso()
        cases.append(case)
        self.save({"cases": cases})
        return case


def build_run_record(summary: Mapping[str, object]) -> dict[str, object]:
    outputs = summary.get("outputs") if isinstance(summary.get("outputs"), Mapping) else {}
    summary_path = str(outputs.get("summary") or "")
    return {
        "run_id": Path(summary_path).parent.name if summary_path else "",
        "mode": str(summary.get("mode") or ""),
        "root": str(summary.get("root") or ""),
        "output_dir": str(summary.get("output_dir") or Path(summary_path).parent if summary_path else ""),
        "summary_path": summary_path,
        "added_at": now_iso(),
        "counts": summary.get("summary") if isinstance(summary.get("summary"), Mapping) else {},
    }


def default_case_catalog_path() -> Path:
    return Path.home() / ".rapidtriage" / "case-catalog.json"
