"""Complete-history duplicate detection behind an abstract provider."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Protocol

from .model import Command, CommandError

MAX_HISTORY_PAGES = 100
MAX_HISTORY_RECORDS = 10_000


class HistoryError(RuntimeError):
    """History cannot be proven complete and trustworthy."""


class DuplicateCommandError(HistoryError):
    """A semantically identical consumed command already exists."""


@dataclass(frozen=True, slots=True)
class HistoryPage:
    records: tuple[Mapping[str, Any], ...]
    next_cursor: str | None
    complete: bool


class HistoryProvider(Protocol):
    def fetch_page(self, cursor: str | None) -> HistoryPage: ...


def assert_not_consumed(command: Command, provider: HistoryProvider) -> None:
    """Fail closed unless all history is read and no consumed duplicate exists."""
    cursor: str | None = None
    seen_cursors: set[str] = set()
    pages = 0
    records = 0

    while True:
        pages += 1
        if pages > MAX_HISTORY_PAGES:
            raise HistoryError("history page limit exceeded")
        try:
            page = provider.fetch_page(cursor)
        except Exception as error:
            raise HistoryError(f"history provider failed: {error}") from error
        if not isinstance(page, HistoryPage):
            raise HistoryError("history provider returned an invalid page")

        for raw in page.records:
            records += 1
            if records > MAX_HISTORY_RECORDS:
                raise HistoryError("history record limit exceeded")
            if not isinstance(raw, Mapping):
                raise HistoryError("history record container is malformed")
            consumed = raw.get("consumed")
            prior_raw = raw.get("command")
            if type(consumed) is not bool or not isinstance(prior_raw, Mapping):
                raise HistoryError("history record envelope is malformed")
            if not consumed:
                continue
            try:
                prior = Command.from_mapping(prior_raw)
            except CommandError:
                # A prior invalid request never consumed a valid semantic identity.
                continue
            if prior.identity == command.identity:
                raise DuplicateCommandError("semantically identical command already consumed")

        if page.next_cursor is None:
            if not page.complete:
                raise HistoryError("history ended without completeness proof")
            return
        if page.complete:
            raise HistoryError("history page cannot be complete while advertising a next cursor")
        if not isinstance(page.next_cursor, str) or not page.next_cursor:
            raise HistoryError("history cursor is invalid")
        if page.next_cursor in seen_cursors:
            raise HistoryError("history cursor loop detected")
        seen_cursors.add(page.next_cursor)
        cursor = page.next_cursor


class StaticHistoryProvider:
    """Deterministic local/test provider keyed by cursor."""

    def __init__(self, pages: Mapping[str | None, HistoryPage]) -> None:
        self._pages = dict(pages)

    def fetch_page(self, cursor: str | None) -> HistoryPage:
        try:
            return self._pages[cursor]
        except KeyError as error:
            raise HistoryError(f"missing history page for cursor {cursor!r}") from error
