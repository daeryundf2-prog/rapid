"""Cross-device IOC correlation routes (R4-2)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query

from ...core.cross_device import build_cross_device_ioc_package
from ...core.jobs import RunJobStore


def build_ioc_router(store: RunJobStore) -> APIRouter:
    router = APIRouter()

    @router.get("/api/ioc/cross-device")
    def cross_device_ioc(
        run_ids: str | None = Query(default=None, description="Comma-separated run ids; default all runs"),
        min_runs: int = Query(default=2, ge=1, le=50),
        max_shared: int = Query(default=500, ge=1, le=5000),
    ) -> dict[str, Any]:
        requested = {item.strip() for item in (run_ids or "").split(",") if item.strip()}
        entries: list[dict[str, object]] = []
        for job in store.list():
            if requested and job.run_id not in requested:
                continue
            label = getattr(job.request, "root", "") or job.run_id
            try:
                payload = store.read_output(job.run_id, "indicators")
            except (KeyError, RuntimeError, PermissionError, FileNotFoundError):
                payload = {}
            indicators = payload.get("indicators") if isinstance(payload, dict) else []
            entries.append(
                {
                    "run_id": job.run_id,
                    "label": str(label),
                    "root": str(label),
                    "indicators": indicators or [],
                }
            )
        return build_cross_device_ioc_package(
            entries,
            min_runs=min_runs,
            max_shared=max_shared,
        )

    return router
