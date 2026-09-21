"""Pure reviewed-command model and stable semantic identity."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Mapping

MAX_COMMAND_BYTES = 32 * 1024
_ALLOWED_FIELDS = {"version", "action", "runbook", "arguments", "mutation"}


class CommandError(ValueError):
    """The command or review context is malformed or violates review policy."""


def canonical_json(value: Any) -> bytes:
    """Canonical JSON: object keys sorted recursively; list order preserved."""
    try:
        payload = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise CommandError(f"value is not canonical JSON: {error}") from error
    return payload


def digest_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


@dataclass(frozen=True, slots=True)
class Command:
    version: str
    action: str
    runbook: str
    arguments: Mapping[str, Any]
    mutation: bool

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> "Command":
        if not isinstance(raw, Mapping):
            raise CommandError("command must be an object")
        unknown = set(raw) - _ALLOWED_FIELDS
        missing = _ALLOWED_FIELDS - set(raw)
        if unknown or missing:
            raise CommandError(
                f"command fields mismatch: missing={sorted(missing)}, unknown={sorted(unknown)}"
            )
        if len(canonical_json(raw)) > MAX_COMMAND_BYTES:
            raise CommandError("command exceeds size limit")
        for field in ("version", "action", "runbook"):
            value = raw[field]
            if not isinstance(value, str) or not value or len(value) > 256:
                raise CommandError(f"{field} must be a non-empty bounded string")
        arguments = raw["arguments"]
        if not isinstance(arguments, Mapping):
            raise CommandError("arguments must be an object")
        mutation = raw["mutation"]
        if type(mutation) is not bool:
            raise CommandError("mutation must be boolean")
        return cls(
            version=raw["version"],
            action=raw["action"],
            runbook=raw["runbook"],
            arguments=dict(arguments),
            mutation=mutation,
        )

    def as_mapping(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "arguments": dict(self.arguments),
            "mutation": self.mutation,
            "runbook": self.runbook,
            "version": self.version,
        }

    @property
    def identity(self) -> str:
        """Stable operational-intent identity independent of reviewer/transport context."""
        return digest_json(self.as_mapping())


@dataclass(frozen=True, slots=True)
class ReviewContext:
    """Authenticated/validated review context supplied independently of command payload."""

    reviewer: str
    context_id: str

    def __post_init__(self) -> None:
        for field, value in (("reviewer", self.reviewer), ("context_id", self.context_id)):
            if not isinstance(value, str) or not value or len(value) > 256:
                raise CommandError(f"{field} must be a non-empty bounded string")

    def as_mapping(self) -> dict[str, str]:
        return {"context_id": self.context_id, "reviewer": self.reviewer}


@dataclass(frozen=True, slots=True)
class ActionPolicy:
    runbook: str
    mutation: bool


@dataclass(frozen=True, slots=True)
class ReviewPolicy:
    allowed_reviewers: frozenset[str]
    actions: Mapping[str, ActionPolicy]

    def validate(self, command: Command, review: ReviewContext) -> str:
        if command.version != "v1":
            raise CommandError("unsupported command version")
        if review.reviewer not in self.allowed_reviewers:
            raise CommandError("reviewer is not allowed")
        rule = self.actions.get(command.action)
        if rule is None:
            raise CommandError("action is not allowed")
        if command.runbook != rule.runbook:
            raise CommandError("runbook does not match the allowed action")
        if command.mutation != rule.mutation:
            raise CommandError("mutation classification does not match the allowed action")
        return digest_json(
            {
                "reviewers": sorted(self.allowed_reviewers),
                "actions": {
                    name: {"runbook": item.runbook, "mutation": item.mutation}
                    for name, item in sorted(self.actions.items())
                },
            }
        )
