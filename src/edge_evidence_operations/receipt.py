"""Structured execution receipts and stable identities."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path

from .model import digest_json


@dataclass(frozen=True, slots=True)
class Receipt:
    command_id: str
    review_id: str
    authorization_id: str
    execution_id: str | None
    runbook: str
    runbook_digest: str
    outcome: str
    exit_code: int | None
    mutation: bool
    partial_state: bool
    evidence_digest: str
    retry_authorized: bool = False
    rollback_performed: bool = False

    def as_dict(self) -> dict[str, object]:
        return asdict(self)

    @property
    def receipt_digest(self) -> str:
        return digest_json(self.as_dict())

    def write(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.as_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
