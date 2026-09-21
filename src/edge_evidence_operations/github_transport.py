"""Pure caller-supplied GitHub-like transport projection with no network authority."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Mapping

from .control import Authorization, ControlPlane
from .history import HistoryError, HistoryPage, HistoryProvider
from .model import Command, CommandError, ReviewContext, digest_json

MAX_BODY_BYTES = 32 * 1024
DEFAULT_PREFIX = "ops-review "
_REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")
_ACTOR = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")
_ALLOWED_COMMENT_FIELDS = {"repository", "issue", "comment_id", "actor", "body"}
_ALLOWED_PAGE_FIELDS = {"comments", "next_cursor", "complete"}


class TransportError(ValueError):
    """Caller-supplied transport data is malformed or outside reviewed policy."""


@dataclass(frozen=True, slots=True)
class CommentEnvelope:
    repository: str
    issue: int
    comment_id: int
    actor: str
    body: str

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> "CommentEnvelope":
        if not isinstance(raw, Mapping):
            raise TransportError("comment envelope must be an object")
        if set(raw) != _ALLOWED_COMMENT_FIELDS:
            raise TransportError("comment envelope fields do not match the v1 transport contract")
        repository = raw["repository"]
        actor = raw["actor"]
        body = raw["body"]
        issue = raw["issue"]
        comment_id = raw["comment_id"]
        if not isinstance(repository, str) or not _REPOSITORY.fullmatch(repository):
            raise TransportError("repository must be owner/name using bounded public-safe characters")
        if not isinstance(actor, str) or not _ACTOR.fullmatch(actor):
            raise TransportError("actor must be a bounded public-safe identifier")
        if type(issue) is not int or issue <= 0:
            raise TransportError("issue must be a positive integer")
        if type(comment_id) is not int or comment_id <= 0:
            raise TransportError("comment_id must be a positive integer")
        if not isinstance(body, str) or len(body.encode("utf-8")) > MAX_BODY_BYTES:
            raise TransportError("body must be a bounded UTF-8 string")
        return cls(
            repository=repository,
            issue=issue,
            comment_id=comment_id,
            actor=actor,
            body=body,
        )

    @property
    def transport_id(self) -> str:
        return digest_json(
            {
                "actor": self.actor,
                "body_sha256": hashlib.sha256(self.body.encode("utf-8")).hexdigest(),
                "comment_id": self.comment_id,
                "issue": self.issue,
                "repository": self.repository,
            }
        )


@dataclass(frozen=True, slots=True)
class TransportPolicy:
    expected_repository: str
    allowed_issues: frozenset[int]
    allowed_actors: frozenset[str]
    prefix: str = DEFAULT_PREFIX

    def __post_init__(self) -> None:
        if not _REPOSITORY.fullmatch(self.expected_repository):
            raise TransportError("expected_repository must be owner/name")
        if not self.allowed_issues or any(type(item) is not int or item <= 0 for item in self.allowed_issues):
            raise TransportError("allowed_issues must contain positive integers")
        if not self.allowed_actors or any(not _ACTOR.fullmatch(item) for item in self.allowed_actors):
            raise TransportError("allowed_actors must contain bounded identifiers")
        if (
            not isinstance(self.prefix, str)
            or not self.prefix.endswith(" ")
            or self.prefix.strip() == ""
            or len(self.prefix) > 40
            or "/" in self.prefix
            or not re.fullmatch(r"[A-Za-z0-9_-]+ ", self.prefix)
        ):
            raise TransportError("prefix must be a short generic token followed by one space")

    def validate_envelope(self, envelope: CommentEnvelope) -> None:
        if envelope.repository != self.expected_repository:
            raise TransportError("repository does not match transport policy")
        if envelope.issue not in self.allowed_issues:
            raise TransportError("issue is not allowed by transport policy")
        if envelope.actor not in self.allowed_actors:
            raise TransportError("actor is not allowed by transport policy")

    def command_from_envelope(self, envelope: CommentEnvelope) -> Command:
        self.validate_envelope(envelope)
        if not envelope.body.startswith(self.prefix):
            raise TransportError("comment does not contain the reviewed generic command prefix")
        payload_text = envelope.body[len(self.prefix) :].strip()
        if not payload_text:
            raise TransportError("command payload is empty")
        try:
            payload = json.loads(payload_text)
        except json.JSONDecodeError as error:
            raise TransportError("command payload is invalid JSON") from error
        if not isinstance(payload, Mapping):
            raise TransportError("command payload must be an object")
        try:
            return Command.from_mapping(payload)
        except CommandError as error:
            raise TransportError(f"command payload violates the core contract: {error}") from error

    def review_context_from_envelope(self, envelope: CommentEnvelope) -> ReviewContext:
        """Derive review identity from validated transport context, never command payload."""
        self.validate_envelope(envelope)
        return ReviewContext(reviewer=envelope.actor, context_id=envelope.transport_id)


@dataclass(frozen=True, slots=True)
class TransportHistoryPage:
    comments: tuple[Mapping[str, Any], ...]
    next_cursor: str | None
    complete: bool

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> "TransportHistoryPage":
        if not isinstance(raw, Mapping) or set(raw) != _ALLOWED_PAGE_FIELDS:
            raise TransportError("history page fields do not match the v1 transport contract")
        comments = raw["comments"]
        next_cursor = raw["next_cursor"]
        complete = raw["complete"]
        if not isinstance(comments, list) or any(not isinstance(item, Mapping) for item in comments):
            raise TransportError("history comments must be a list of objects")
        if next_cursor is not None and (not isinstance(next_cursor, str) or not next_cursor):
            raise TransportError("next_cursor must be null or a non-empty string")
        if type(complete) is not bool:
            raise TransportError("complete must be boolean")
        return cls(comments=tuple(comments), next_cursor=next_cursor, complete=complete)


class OfflineCommentHistoryProvider(HistoryProvider):
    """Adapts supplied prior comments; it never observes GitHub itself."""

    def __init__(
        self,
        pages: Mapping[str | None, TransportHistoryPage],
        policy: TransportPolicy,
    ) -> None:
        self._pages = dict(pages)
        self._policy = policy

    @classmethod
    def from_fixture(
        cls,
        raw: Mapping[str, Any],
        policy: TransportPolicy,
    ) -> "OfflineCommentHistoryProvider":
        pages_raw = raw.get("pages") if isinstance(raw, Mapping) else None
        if not isinstance(pages_raw, list) or not pages_raw:
            raise TransportError("history fixture must contain a non-empty pages list")
        pages: dict[str | None, TransportHistoryPage] = {}
        for item in pages_raw:
            if not isinstance(item, Mapping) or set(item) != {
                "cursor",
                "comments",
                "next_cursor",
                "complete",
            }:
                raise TransportError("history fixture page envelope is malformed")
            cursor = item["cursor"]
            if cursor is not None and (not isinstance(cursor, str) or not cursor):
                raise TransportError("history fixture cursor must be null or a non-empty string")
            if cursor in pages:
                raise TransportError("history fixture cursor is duplicated")
            pages[cursor] = TransportHistoryPage.from_mapping(
                {
                    "comments": item["comments"],
                    "next_cursor": item["next_cursor"],
                    "complete": item["complete"],
                }
            )
        if None not in pages:
            raise TransportError("history fixture must contain the initial null cursor")
        return cls(pages, policy)

    def fetch_page(self, cursor: str | None) -> HistoryPage:
        try:
            page = self._pages[cursor]
        except KeyError as error:
            raise HistoryError(f"missing supplied transport history page for cursor {cursor!r}") from error

        records: list[Mapping[str, Any]] = []
        for raw in page.comments:
            try:
                envelope = CommentEnvelope.from_mapping(raw)
            except TransportError as error:
                raise HistoryError(f"malformed supplied comment envelope: {error}") from error

            try:
                command = self._policy.command_from_envelope(envelope)
            except TransportError:
                records.append({"consumed": False, "command": {}})
                continue
            records.append({"consumed": True, "command": command.as_mapping()})

        return HistoryPage(
            records=tuple(records),
            next_cursor=page.next_cursor,
            complete=page.complete,
        )


@dataclass(frozen=True, slots=True)
class DispatchIntent:
    transport_id: str
    command_id: str
    review_id: str
    authorization_id: str
    runbook: str
    runbook_digest: str
    action: str
    mutation: bool
    evidence_digest: str
    retry_authorized: bool = False

    def as_dict(self) -> dict[str, object]:
        return {
            "action": self.action,
            "authorization_id": self.authorization_id,
            "command_id": self.command_id,
            "evidence_digest": self.evidence_digest,
            "mutation": self.mutation,
            "retry_authorized": self.retry_authorized,
            "review_id": self.review_id,
            "runbook": self.runbook,
            "runbook_digest": self.runbook_digest,
            "transport_id": self.transport_id,
        }


def build_dispatch_intent(envelope: CommentEnvelope, authorization: Authorization) -> DispatchIntent:
    evidence = {
        "action": authorization.command.action,
        "authorization_id": authorization.authorization_id,
        "command_id": authorization.command_id,
        "mutation": authorization.command.mutation,
        "review_id": authorization.review_id,
        "runbook": authorization.runbook.name,
        "runbook_digest": authorization.runbook.digest,
        "transport_id": envelope.transport_id,
    }
    return DispatchIntent(
        transport_id=envelope.transport_id,
        command_id=authorization.command_id,
        review_id=authorization.review_id,
        authorization_id=authorization.authorization_id,
        runbook=authorization.runbook.name,
        runbook_digest=authorization.runbook.digest,
        action=authorization.command.action,
        mutation=authorization.command.mutation,
        evidence_digest=digest_json(evidence),
    )


def authorize_comment(
    control: ControlPlane,
    envelope: CommentEnvelope,
    policy: TransportPolicy,
    history: HistoryProvider,
) -> tuple[Authorization, DispatchIntent]:
    """Authorize one caller-supplied comment and render inert dispatch intent."""
    command = policy.command_from_envelope(envelope)
    review_context = policy.review_context_from_envelope(envelope)
    authorization = control.authorize(command, review_context, history)
    return authorization, build_dispatch_intent(envelope, authorization)
