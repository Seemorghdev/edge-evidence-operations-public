"""Exact versioned local runbook registry with digest binding."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping


class RegistryError(RuntimeError):
    """A requested runbook is not exactly registered and stable."""


@dataclass(frozen=True, slots=True)
class RunbookSnapshot:
    name: str
    path: Path
    digest: str


class RunbookRegistry:
    def __init__(self, root: Path, entries: Mapping[str, str]) -> None:
        self.root = root.resolve()
        self.entries = dict(entries)

    def snapshot(self, name: str) -> RunbookSnapshot:
        relative = self.entries.get(name)
        if relative is None:
            raise RegistryError("runbook is not registered")
        rel_path = Path(relative)
        if rel_path.is_absolute() or ".." in rel_path.parts:
            raise RegistryError("registered runbook path is unsafe")

        candidate = self.root / rel_path
        if candidate.is_symlink():
            raise RegistryError("runbook symlinks are forbidden")
        try:
            path = candidate.resolve(strict=True)
        except (FileNotFoundError, RuntimeError, OSError) as error:
            raise RegistryError("registered runbook is missing or unsafe") from error
        if path.parent != self.root or not path.is_file():
            raise RegistryError("runbook must be one regular file directly in registry root")

        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        return RunbookSnapshot(name=name, path=path, digest=digest)

    def assert_unchanged(self, snapshot: RunbookSnapshot) -> None:
        current = self.snapshot(snapshot.name)
        if current.path != snapshot.path or current.digest != snapshot.digest:
            raise RegistryError("runbook bytes changed after authorization")
