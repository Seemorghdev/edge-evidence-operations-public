"""Fail-closed structured evidence sanitizer."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping


class SanitizationError(RuntimeError):
    """Evidence cannot be proven safe for retention."""


_SENSITIVE_NAME = re.compile(r"token|secret|password|credential|private[_-]?key|authorization", re.I)
_WIF_PATH = "workloadIdentity" + "Pools/"
_SENSITIVE_VALUE = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|"
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.iam\.gserviceaccount\.com\b|"
    r"\.pkg\.dev/|" + re.escape(_WIF_PATH),
    re.I,
)


@dataclass(frozen=True, slots=True)
class EvidenceSanitizer:
    allowed_fields: frozenset[str]

    def sanitize(self, raw: Mapping[str, Any]) -> dict[str, Any]:
        if not isinstance(raw, Mapping):
            raise SanitizationError("evidence must be an object")
        unknown = set(raw) - self.allowed_fields
        if unknown:
            raise SanitizationError(f"unknown evidence fields are refused: {sorted(unknown)}")
        clean: dict[str, Any] = {}
        for key, value in raw.items():
            if _SENSITIVE_NAME.search(key):
                raise SanitizationError(f"sensitive evidence field refused: {key}")
            if not isinstance(value, (str, int, bool)) and value is not None:
                raise SanitizationError(f"unsupported evidence type for {key}")
            if isinstance(value, str) and _SENSITIVE_VALUE.search(value):
                raise SanitizationError(f"sensitive evidence value refused in {key}")
            clean[key] = value
        return clean
