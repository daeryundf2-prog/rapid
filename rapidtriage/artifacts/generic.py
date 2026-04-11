from __future__ import annotations

from pathlib import Path
from typing import Iterable

from ..core.models import ArtifactRecord


class GenericDocumentArtifactProvider:
    name = "generic-documents"
    description = "Cross-platform document candidates discovered from the filesystem"
    target_platform = "any"

    def supported(self) -> bool:
        return True

    def collect(self, root: Path) -> Iterable[ArtifactRecord]:
        for suffix in (".txt", ".pdf", ".docx"):
            yield ArtifactRecord(
                provider=self.name,
                artifact_type="document-pattern",
                path=str(root),
                supported=True,
                details={"extension": suffix},
            )
